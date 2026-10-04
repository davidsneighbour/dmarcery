import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import type { Database } from "./db.ts";
import { cidrRange, ipKey, networkOf } from "./ip.ts";
import { isReportFileName, type ReportSource, readReportSources } from "./extract.ts";
import { type DmarcReport, parseReport } from "./parse.ts";
import { safeComponent } from "./paths.ts";

export type FindingKind =
  | "new_source_ip"
  | "new_network"
  | "new_header_from"
  | "new_dkim_domain"
  | "new_dkim_selector"
  | "new_spf_domain"
  | "unregistered_sender"
  | "dmarc_failure"
  | "volume_change";

export interface Finding {
  kind: FindingKind;
  value: string;
  detail?: string;
}

export interface ImportStats {
  records: number;
  messages: number;
  pass: number;
  fail: number;
}

export interface ImportResult {
  file: string;
  status: "imported" | "duplicate" | "conflict";
  report: DmarcReport;
  archivePath?: string;
  stats: ImportStats;
  findings: Finding[];
  message?: string;
}

export interface ImportOptions {
  /** Absolute path of the report archive. */
  archiveDir: string;
  /** Data directory; archive paths are stored relative to it. */
  dataDir: string;
  /**
   * When set, the file already lives in the archive at this relative path and
   * is not copied again (used by rebuild).
   */
  archivedAs?: string;
  /** Skip the analysis phase (used by rebuild). */
  analyse?: boolean;
}

function sha256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function decode(data: Buffer): string {
  const text = data.toString("utf8");
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function statsOf(report: DmarcReport): ImportStats {
  let pass = 0;
  let fail = 0;
  for (const record of report.records) {
    if (record.dkimEvaluation === "pass" || record.spfEvaluation === "pass") {
      pass += record.messageCount;
    } else {
      fail += record.messageCount;
    }
  }
  return { records: report.records.length, messages: pass + fail, pass, fail };
}

/** Phase 3: copy the original bytes into the archive, read-only. Returns the path relative to the data directory. */
function preserve(data: Buffer, digest: string, report: DmarcReport, options: ImportOptions): string {
  const begin = new Date(report.periodBegin * 1000);
  const directory = join(
    options.archiveDir,
    safeComponent(report.domain),
    String(begin.getUTCFullYear()),
    String(begin.getUTCMonth() + 1).padStart(2, "0"),
  );
  const stem = `${safeComponent(report.reporter)}-${safeComponent(report.reportId)}`;
  let target = join(directory, `${stem}.xml`);
  if (existsSync(target) && sha256(readFileSync(target)) !== digest) {
    // A different report sanitised to the same name. Never overwrite an archived report.
    target = join(directory, `${stem}-${digest.slice(0, 12)}.xml`);
  }
  if (!existsSync(target)) {
    mkdirSync(directory, { recursive: true });
    const temporary = `${target}.${process.pid}.tmp`;
    writeFileSync(temporary, data, { mode: 0o444 });
    renameSync(temporary, target);
  }
  chmodSync(target, 0o444);
  return relative(options.dataDir, target);
}

/** Phase 4: insert the report and all records in one transaction. Returns the reports.id. */
function insert(db: Database, report: DmarcReport, sourceFile: string, archivePath: string, digest: string): number {
  return db.transaction(() => {
    const reportPk = db.run(
      `INSERT INTO reports (
         reporter, report_id, report_email, extra_contact_info, report_version, report_errors,
         domain, period_begin, period_end,
         policy_adkim, policy_aspf, policy_p, policy_sp, policy_pct, policy_np, policy_fo,
         source_file, archive_path, source_sha256, imported_at
       ) VALUES (
         :reporter, :report_id, :report_email, :extra_contact_info, :report_version, :report_errors,
         :domain, :period_begin, :period_end,
         :adkim, :aspf, :p, :sp, :pct, :np, :fo,
         :source_file, :archive_path, :sha, :imported_at
       )`,
      {
        reporter: report.reporter,
        report_id: report.reportId,
        report_email: report.reportEmail,
        extra_contact_info: report.extraContactInfo,
        report_version: report.version,
        report_errors: report.errors.length > 0 ? JSON.stringify(report.errors) : null,
        domain: report.domain,
        period_begin: report.periodBegin,
        period_end: report.periodEnd,
        adkim: report.policy.adkim,
        aspf: report.policy.aspf,
        p: report.policy.p,
        sp: report.policy.sp,
        pct: report.policy.pct,
        np: report.policy.np,
        fo: report.policy.fo,
        source_file: sourceFile,
        archive_path: archivePath,
        sha: digest,
        imported_at: new Date().toISOString(),
      },
    );

    for (const record of report.records) {
      const recordPk = db.run(
        `INSERT INTO records (
           report_id, source_ip, source_ip_key, message_count, header_from, envelope_from, envelope_to,
           disposition, dkim_evaluation, spf_evaluation
         ) VALUES (
           :report_id, :source_ip, :source_ip_key, :message_count, :header_from, :envelope_from, :envelope_to,
           :disposition, :dkim_evaluation, :spf_evaluation
         )`,
        {
          report_id: reportPk,
          source_ip: record.sourceIp,
          source_ip_key: ipKey(record.sourceIp),
          message_count: record.messageCount,
          header_from: record.headerFrom,
          envelope_from: record.envelopeFrom,
          envelope_to: record.envelopeTo,
          disposition: record.disposition,
          dkim_evaluation: record.dkimEvaluation,
          spf_evaluation: record.spfEvaluation,
        },
      );
      for (const reason of record.reasons) {
        db.run("INSERT INTO policy_reasons (record_id, type, comment) VALUES (:record_id, :type, :comment)", {
          record_id: recordPk,
          type: reason.type,
          comment: reason.comment,
        });
      }
      for (const dkim of record.dkim) {
        db.run(
          `INSERT INTO dkim_results (record_id, domain, selector, result, human_result)
           VALUES (:record_id, :domain, :selector, :result, :human_result)`,
          {
            record_id: recordPk,
            domain: dkim.domain,
            selector: dkim.selector,
            result: dkim.result,
            human_result: dkim.humanResult,
          },
        );
      }
      for (const spf of record.spf) {
        db.run(
          `INSERT INTO spf_results (record_id, domain, scope, result, human_result)
           VALUES (:record_id, :domain, :scope, :result, :human_result)`,
          {
            record_id: recordPk,
            domain: spf.domain,
            scope: spf.scope,
            result: spf.result,
            human_result: spf.humanResult,
          },
        );
      }
    }
    return reportPk;
  });
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? (sorted[middle] ?? 0) : ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2;
}

/**
 * Phase 5: compare the newly imported report with all other reports.
 * Findings are observations only; nothing is written.
 */
export function analyse(db: Database, reportPk: number, report: DmarcReport): Finding[] {
  const findings: Finding[] = [];
  const pk = { pk: reportPk };
  const values = (sql: string): string[] => db.all(sql, pk).map((row) => String(row["value"]));

  for (const ip of values(`
    SELECT DISTINCT r.source_ip AS value FROM records r
    WHERE r.report_id = :pk AND NOT EXISTS (
      SELECT 1 FROM records o WHERE o.report_id != :pk AND o.source_ip_key = r.source_ip_key)`)) {
    findings.push({ kind: "new_source_ip", value: ip });
  }

  const networks = new Set(report.records.map((record) => networkOf(record.sourceIp)).filter((n) => n !== null));
  for (const network of networks) {
    const range = cidrRange(network);
    if (range === null) {
      continue;
    }
    const seen = db.get(
      "SELECT 1 FROM records WHERE report_id != :pk AND source_ip_key BETWEEN :start AND :end LIMIT 1",
      { pk: reportPk, start: range.start, end: range.end },
    );
    if (seen === undefined) {
      findings.push({ kind: "new_network", value: network });
    }
  }

  for (const domain of values(`
    SELECT DISTINCT r.header_from AS value FROM records r
    WHERE r.report_id = :pk AND r.header_from IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM records o WHERE o.report_id != :pk AND o.header_from = r.header_from)`)) {
    findings.push({ kind: "new_header_from", value: domain });
  }

  for (const domain of values(`
    SELECT DISTINCT d.domain AS value FROM dkim_results d JOIN records r ON r.id = d.record_id
    WHERE r.report_id = :pk AND d.domain IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM dkim_results od JOIN records o ON o.id = od.record_id
      WHERE o.report_id != :pk AND od.domain = d.domain)`)) {
    findings.push({ kind: "new_dkim_domain", value: domain });
  }

  for (const selector of values(`
    SELECT DISTINCT d.selector || '._domainkey.' || d.domain AS value FROM dkim_results d JOIN records r ON r.id = d.record_id
    WHERE r.report_id = :pk AND d.selector IS NOT NULL AND d.domain IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM dkim_results od JOIN records o ON o.id = od.record_id
      WHERE o.report_id != :pk AND od.domain = d.domain AND od.selector = d.selector)`)) {
    findings.push({ kind: "new_dkim_selector", value: selector });
  }

  for (const domain of values(`
    SELECT DISTINCT s.domain AS value FROM spf_results s JOIN records r ON r.id = s.record_id
    WHERE r.report_id = :pk AND s.domain IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM spf_results os JOIN records o ON o.id = os.record_id
      WHERE o.report_id != :pk AND os.domain = s.domain)`)) {
    findings.push({ kind: "new_spf_domain", value: domain });
  }

  // Registry checks only make sense once the registry has entries.
  const registered = db.get("SELECT count(*) AS n FROM senders");
  if (Number(registered?.["n"] ?? 0) > 0) {
    for (const row of db.all(
      `SELECT source_ip, header_from, sum(message_count) AS messages FROM v_records v
       WHERE report_pk = :pk AND NOT EXISTS (
         SELECT 1 FROM v_record_sender_matches m JOIN senders s ON s.id = m.sender_id
         WHERE m.record_id = v.record_id AND s.status IN ('known', 'ignored'))
       GROUP BY source_ip, header_from`,
      pk,
    )) {
      findings.push({
        kind: "unregistered_sender",
        value: String(row["source_ip"]),
        detail: `header-from ${String(row["header_from"] ?? "?")}, ${String(row["messages"])} messages`,
      });
    }
  }

  for (const row of db.all(
    `SELECT source_ip, header_from, message_count, dkim_evaluation, spf_evaluation, disposition, dkim_auth, spf_auth
     FROM v_records WHERE report_pk = :pk AND dmarc_result = 'fail' ORDER BY message_count DESC`,
    pk,
  )) {
    findings.push({
      kind: "dmarc_failure",
      value: String(row["source_ip"]),
      detail: [
        `header-from: ${String(row["header_from"] ?? "?")}`,
        `messages: ${String(row["message_count"])}`,
        `DKIM ${String(row["dkim_evaluation"] ?? "?")} (${String(row["dkim_auth"] ?? "no signature")})`,
        `SPF ${String(row["spf_evaluation"] ?? "?")} (${String(row["spf_auth"] ?? "no result")})`,
        `disposition: ${String(row["disposition"] ?? "?")}`,
      ].join("\n"),
    });
  }

  // Volume: compare with the median of the previous 30 reports from the same reporter for the same domain.
  const previous = db
    .all(
      `SELECT coalesce(sum(r.message_count), 0) AS messages FROM reports rep
       LEFT JOIN records r ON r.report_id = rep.id
       WHERE rep.id != :pk AND rep.reporter = :reporter AND rep.domain = :domain AND rep.period_begin < :begin
       GROUP BY rep.id ORDER BY rep.period_begin DESC LIMIT 30`,
      { pk: reportPk, reporter: report.reporter, domain: report.domain, begin: report.periodBegin },
    )
    .map((row) => Number(row["messages"]));
  if (previous.length >= 3) {
    const typical = median(previous);
    const { messages } = statsOf(report);
    const increased = messages >= Math.max(3 * typical, typical + 10);
    const decreased = typical >= 10 && messages <= typical / 3;
    if (increased || decreased) {
      findings.push({
        kind: "volume_change",
        value: `${messages} messages`,
        detail: `median of previous ${previous.length} reports: ${typical}`,
      });
    }
  }

  return findings;
}

/** Imports one XML report. Follows the import protocol in PLAN.md section 9. */
export function importReport(db: Database, source: ReportSource, options: ImportOptions): ImportResult {
  const file = source.name;
  const data = source.data;

  // Phase 1: validate.
  const report = parseReport(decode(data));
  const stats = statsOf(report);

  // Phase 2: fingerprint. The checksum covers the XML, so a report delivered as .xml, .gz, or .zip is one report.
  const digest = sha256(data);
  const existing = db.get(
    `SELECT reporter, report_id, source_sha256, archive_path FROM reports
     WHERE (reporter = :reporter AND report_id = :report_id) OR source_sha256 = :sha`,
    { reporter: report.reporter, report_id: report.reportId, sha: digest },
  );
  if (existing !== undefined) {
    if (existing["source_sha256"] === digest) {
      return { file, status: "duplicate", report, archivePath: String(existing["archive_path"]), stats, findings: [] };
    }
    return {
      file,
      status: "conflict",
      report,
      stats,
      findings: [],
      message: `report ${report.reporter} ${report.reportId} is already imported with different content (${String(existing["archive_path"])})`,
    };
  }

  // Phase 3: preserve, before the database changes.
  const archivePath = options.archivedAs ?? preserve(data, digest, report, options);

  // Phase 4: parse into the database.
  const reportPk = insert(db, report, source.sourceFile, archivePath, digest);

  // Phase 5: analyse.
  const findings = options.analyse === false ? [] : analyse(db, reportPk, report);

  return { file, status: "imported", report, archivePath, stats, findings };
}

/** Imports every report in a .xml, .xml.gz, or .zip file. Stops at the first invalid report. */
export function importFile(db: Database, path: string, options: ImportOptions): ImportResult[] {
  return readReportSources(path).map((source) => importReport(db, source, options));
}

/** Expands files and directories into a sorted list of report files. */
export function collectFiles(paths: string[], recursive: boolean): string[] {
  const files: string[] = [];
  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (recursive) {
          walk(path);
        }
      } else if (entry.isFile() && isReportFileName(entry.name)) {
        files.push(path);
      }
    }
  };
  for (const path of paths) {
    if (statSync(path).isDirectory()) {
      walk(path);
    } else {
      files.push(path);
    }
  }
  return files;
}
