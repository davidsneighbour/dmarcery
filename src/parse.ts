import { XMLParser, XMLValidator } from "fast-xml-parser";

export interface DkimResult {
  domain: string | null;
  selector: string | null;
  result: string | null;
  humanResult: string | null;
}

export interface SpfResult {
  domain: string | null;
  scope: string | null;
  result: string | null;
  humanResult: string | null;
}

export interface OverrideReason {
  type: string | null;
  comment: string | null;
}

export interface DmarcRecord {
  sourceIp: string;
  messageCount: number;
  headerFrom: string | null;
  envelopeFrom: string | null;
  envelopeTo: string | null;
  disposition: string | null;
  dkimEvaluation: string | null;
  spfEvaluation: string | null;
  reasons: OverrideReason[];
  dkim: DkimResult[];
  spf: SpfResult[];
}

export interface DmarcReport {
  version: string | null;
  reporter: string;
  reportId: string;
  reportEmail: string | null;
  extraContactInfo: string | null;
  errors: string[];
  periodBegin: number;
  periodEnd: number;
  domain: string;
  policy: {
    adkim: string | null;
    aspf: string | null;
    p: string | null;
    sp: string | null;
    pct: number | null;
    np: string | null;
    fo: string | null;
  };
  records: DmarcRecord[];
}

export class ReportError extends Error {
  override name = "ReportError";
}

const ARRAY_PATHS = new Set([
  "feedback.record",
  "feedback.report_metadata.error",
  "feedback.record.row.policy_evaluated.reason",
  "feedback.record.auth_results.dkim",
  "feedback.record.auth_results.spf",
]);

const parser = new XMLParser({
  ignoreAttributes: true,
  ignoreDeclaration: true,
  ignorePiTags: true,
  removeNSPrefix: true,
  parseTagValue: false,
  trimValues: true,
  isArray: (_tagName, jPath) => ARRAY_PATHS.has(String(jPath)),
});

type Node = Record<string, unknown>;

function isNode(value: unknown): value is Node {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function child(node: unknown, key: string): Node | undefined {
  if (!isNode(node)) {
    return undefined;
  }
  const value = node[key];
  return isNode(value) ? value : undefined;
}

function children(node: unknown, key: string): Node[] {
  if (!isNode(node)) {
    return [];
  }
  const value = node[key];
  return Array.isArray(value) ? value.filter(isNode) : [];
}

function text(node: unknown, key: string): string | null {
  if (!isNode(node)) {
    return null;
  }
  const value = node[key];
  if (typeof value === "string" || typeof value === "number") {
    const result = String(value).trim();
    return result === "" ? null : result;
  }
  return null;
}

function lower(value: string | null): string | null {
  return value === null ? null : value.toLowerCase();
}

function integer(value: string | null, field: string): number {
  if (value === null || !/^\d+$/.test(value)) {
    throw new ReportError(`Invalid or missing ${field}: ${value ?? "(empty)"}`);
  }
  return Number.parseInt(value, 10);
}

function optionalInteger(value: string | null): number | null {
  return value !== null && /^\d+$/.test(value)
    ? Number.parseInt(value, 10)
    : null;
}

function required(value: string | null, field: string): string {
  if (value === null) {
    throw new ReportError(`Missing ${field}`);
  }
  return value;
}

function parseRecord(node: Node): DmarcRecord {
  const row = child(node, "row");
  const evaluated = child(row, "policy_evaluated");
  const identifiers = child(node, "identifiers");
  const auth = child(node, "auth_results");

  return {
    sourceIp: required(text(row, "source_ip"), "record/row/source_ip"),
    messageCount: integer(text(row, "count"), "record/row/count"),
    headerFrom: lower(text(identifiers, "header_from")),
    envelopeFrom: lower(text(identifiers, "envelope_from")),
    envelopeTo: lower(text(identifiers, "envelope_to")),
    disposition: lower(text(evaluated, "disposition")),
    dkimEvaluation: lower(text(evaluated, "dkim")),
    spfEvaluation: lower(text(evaluated, "spf")),
    reasons: children(evaluated, "reason").map((reason) => ({
      type: lower(text(reason, "type")),
      comment: text(reason, "comment"),
    })),
    dkim: children(auth, "dkim").map((dkim) => ({
      domain: lower(text(dkim, "domain")),
      selector: lower(text(dkim, "selector")),
      result: lower(text(dkim, "result")),
      humanResult: text(dkim, "human_result"),
    })),
    spf: children(auth, "spf").map((spf) => ({
      domain: lower(text(spf, "domain")),
      scope: lower(text(spf, "scope")),
      result: lower(text(spf, "result")),
      humanResult: text(spf, "human_result"),
    })),
  };
}

/**
 * Validates and parses a DMARC aggregate report (RFC 7489, appendix C).
 * Throws ReportError for files that are not DMARC aggregate reports.
 */
export function parseReport(xml: string): DmarcReport {
  const valid = XMLValidator.validate(xml);
  if (valid !== true) {
    throw new ReportError(
      `Not well-formed XML: ${valid.err.msg} (line ${valid.err.line})`,
    );
  }

  const document: unknown = parser.parse(xml);
  const feedback = child(document, "feedback");
  if (feedback === undefined) {
    throw new ReportError(
      "Not a DMARC aggregate report: missing <feedback> root element",
    );
  }
  const metadata = child(feedback, "report_metadata");
  if (metadata === undefined) {
    throw new ReportError(
      "Not a DMARC aggregate report: missing <report_metadata>",
    );
  }
  const policy = child(feedback, "policy_published");
  if (policy === undefined) {
    throw new ReportError(
      "Not a DMARC aggregate report: missing <policy_published>",
    );
  }
  const dateRange = child(metadata, "date_range");

  const errors =
    isNode(metadata) && Array.isArray(metadata["error"])
      ? metadata["error"]
      : [];

  return {
    version: text(feedback, "version"),
    reporter: required(text(metadata, "org_name"), "report_metadata/org_name"),
    reportId: required(
      text(metadata, "report_id"),
      "report_metadata/report_id",
    ),
    reportEmail: text(metadata, "email"),
    extraContactInfo: text(metadata, "extra_contact_info"),
    errors: errors
      .map((error) => String(error).trim())
      .filter((error) => error !== ""),
    periodBegin: integer(
      text(dateRange, "begin"),
      "report_metadata/date_range/begin",
    ),
    periodEnd: integer(
      text(dateRange, "end"),
      "report_metadata/date_range/end",
    ),
    domain: required(
      text(policy, "domain"),
      "policy_published/domain",
    ).toLowerCase(),
    policy: {
      adkim: lower(text(policy, "adkim")),
      aspf: lower(text(policy, "aspf")),
      p: lower(text(policy, "p")),
      sp: lower(text(policy, "sp")),
      pct: optionalInteger(text(policy, "pct")),
      np: lower(text(policy, "np")),
      fo: text(policy, "fo"),
    },
    records: children(feedback, "record").map(parseRecord),
  };
}
