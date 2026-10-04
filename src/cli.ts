#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { Database } from "./db.ts";
import { type ReportSource, readReportSources } from "./extract.ts";
import {
  type Column,
  formatDateTime,
  formatNumber,
  pairs,
  table,
} from "./format.ts";
import {
  collectFiles,
  type Finding,
  type FindingKind,
  type ImportResult,
  importReport,
} from "./importer.ts";
import { ReportError } from "./parse.ts";
import { type DataPaths, resolvePaths } from "./paths.ts";
import {
  anomalies,
  type Counted,
  type Filter,
  inspectSender,
  listDaily,
  listDomains,
  listFailures,
  listReports,
  listUnknown,
  summary,
} from "./queries.ts";
import { rebuild } from "./rebuild.ts";
import {
  addSender,
  type Identifier,
  type IdentifierType,
  isSenderStatus,
  listSenders,
  RegistryError,
  removeSender,
  SENDER_STATUSES,
} from "./registry.ts";

const HELP = `Usage: dmarc <command> [options]

Import:
  dmarc <file|dir>...                 Import DMARC aggregate reports (same as import)
  dmarc import <file|dir>...          Import .xml, .xml.gz, or .zip reports; directories are
                                      read for *.xml, *.gz, and *.zip
      -r, --recursive                 Also read subdirectories
      -v, --verbose                   Print a full summary for every report

Inspect:
  dmarc summary [--days N]            Totals, and pass/fail for the last N days (default 30)
  dmarc reports                       Recent reports
      --days N  --domain D  --reporter R  --limit N
  dmarc failures [--days N] [--domain D]
                                      Records where DMARC failed
  dmarc unknown [--days N] [--domain D]
                                      Observations not matched by a known or ignored sender
  dmarc sender <ip|cidr|domain>       Everything observed for an IP address, range, or domain
  dmarc daily [--days N] [--domain D] Daily message, pass, and fail counts
  dmarc anomalies [--days N]          New identifiers and trends in the last N days (default 7)
  dmarc domains                       Every domain seen in reports

Sender registry:
  dmarc sender list
  dmarc sender add <name> [--status S] [--notes TEXT] [identifiers]
                                      Create a sender, or update it and add identifiers
  dmarc sender remove <name> [identifiers]
                                      Remove identifiers, or the sender if none are given
      Identifiers (repeatable): --ip, --cidr, --dkim-domain, --dkim-selector,
                                --spf-domain, --header-from
      Statuses: ${SENDER_STATUSES.join(", ")}

Maintenance:
  dmarc rebuild                       Recreate the database from the XML archive

Global options:
  --data-dir DIR    Data directory (default: $DMARC_HOME, else $XDG_DATA_HOME/dmarc,
                    else ~/.local/share/dmarc)
  --json            Machine-readable output
  -h, --help        Show this help
  --version         Show the version
`;

const COMMANDS = new Set([
  "import",
  "summary",
  "reports",
  "failures",
  "unknown",
  "sender",
  "daily",
  "anomalies",
  "domains",
  "rebuild",
  "help",
]);

const IDENTIFIER_OPTIONS: Record<string, IdentifierType> = {
  ip: "source_ip",
  cidr: "source_cidr",
  "dkim-domain": "dkim_domain",
  "dkim-selector": "dkim_selector",
  "spf-domain": "spf_domain",
  "header-from": "header_from",
};

class UsageError extends Error {
  override name = "UsageError";
}

const { values: options, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    "data-dir": { type: "string" },
    json: { type: "boolean", default: false },
    help: { type: "boolean", short: "h", default: false },
    version: { type: "boolean", default: false },
    recursive: { type: "boolean", short: "r", default: false },
    verbose: { type: "boolean", short: "v", default: false },
    days: { type: "string" },
    domain: { type: "string" },
    reporter: { type: "string" },
    limit: { type: "string" },
    status: { type: "string" },
    notes: { type: "string" },
    ip: { type: "string", multiple: true },
    cidr: { type: "string", multiple: true },
    "dkim-domain": { type: "string", multiple: true },
    "dkim-selector": { type: "string", multiple: true },
    "spf-domain": { type: "string", multiple: true },
    "header-from": { type: "string", multiple: true },
  },
});

function positiveInteger(
  value: string | undefined,
  name: string,
): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!/^\d+$/.test(value) || Number(value) < 1) {
    throw new UsageError(`--${name} needs a positive whole number`);
  }
  return Number(value);
}

function filterFromOptions(): Filter {
  const filter: Filter = {};
  const days = positiveInteger(options.days, "days");
  if (days !== undefined) filter.days = days;
  if (options.domain !== undefined) filter.domain = options.domain;
  if (options.reporter !== undefined) filter.reporter = options.reporter;
  return filter;
}

function identifiersFromOptions(): Identifier[] {
  const identifiers: Identifier[] = [];
  for (const [option, type] of Object.entries(IDENTIFIER_OPTIONS)) {
    const values = (options as Record<string, unknown>)[option];
    if (Array.isArray(values)) {
      for (const value of values) {
        identifiers.push({ type, value: String(value) });
      }
    }
  }
  return identifiers;
}

function print(text: string): void {
  process.stdout.write(`${text}\n`);
}

function printJson(value: unknown): void {
  print(
    JSON.stringify(
      value,
      (_key, item: unknown) => (typeof item === "bigint" ? Number(item) : item),
      2,
    ),
  );
}

function printRows(
  columns: Column[],
  rows: Record<string, unknown>[],
  empty: string,
): void {
  if (options.json) {
    printJson(rows);
  } else if (rows.length === 0) {
    print(empty);
  } else {
    print(table(columns, rows));
  }
}

function plural(count: number, word: string): string {
  return `${formatNumber(count)} ${word}${count === 1 ? "" : "s"}`;
}

// --- import -------------------------------------------------------------

const FINDING_LABELS: Record<FindingKind, string> = {
  new_source_ip: "New source IP",
  new_network: "New source network",
  new_header_from: "New header-from",
  new_dkim_domain: "New DKIM domain",
  new_dkim_selector: "New DKIM selector",
  new_spf_domain: "New SPF domain",
  unregistered_sender: "Unknown sender",
  dmarc_failure: "DMARC failure",
  volume_change: "Volume change",
};

function renderFindings(findings: Finding[]): string[] {
  const width =
    Math.max(...Object.values(FINDING_LABELS).map((label) => label.length)) + 2;
  const lines: string[] = [];
  for (const finding of findings) {
    lines.push(
      `${`${FINDING_LABELS[finding.kind]}:`.padEnd(width)}${finding.value}`,
    );
    if (finding.detail !== undefined) {
      for (const line of finding.detail.split("\n")) {
        lines.push(`${" ".repeat(width)}${line}`);
      }
    }
  }
  return lines;
}

function renderImport(result: ImportResult, paths: DataPaths): string {
  const { report, stats } = result;
  const title = `${report.reporter} report ${report.reportId}`;
  if (result.status === "duplicate") {
    return `Already imported — no changes: ${title}`;
  }

  if (options.verbose) {
    const newSenders = result.findings.filter(
      (finding) => finding.kind === "new_source_ip",
    ).length;
    const lines = [
      "DMARC report imported",
      "",
      pairs([
        ["Reporter", report.reporter],
        ["Domain", report.domain],
        [
          "Period",
          `${formatDateTime(report.periodBegin)} — ${formatDateTime(report.periodEnd)} UTC`,
        ],
        ["Report ID", report.reportId],
        [
          "Policy",
          `p=${report.policy.p ?? "?"} sp=${report.policy.sp ?? "-"} pct=${report.policy.pct ?? "-"}`,
        ],
      ]),
      "",
      pairs([
        ["Records", formatNumber(stats.records)],
        ["Messages", formatNumber(stats.messages)],
        ["DMARC pass", formatNumber(stats.pass)],
        ["DMARC fail", formatNumber(stats.fail)],
        ["New senders", formatNumber(newSenders)],
      ]),
    ];
    if (result.findings.length > 0) {
      lines.push("", ...renderFindings(result.findings));
    }
    lines.push(
      "",
      pairs([
        ["Archive", result.archivePath ?? "-"],
        ["Database", paths.database],
      ]),
    );
    return lines.join("\n");
  }

  const date = formatDateTime(report.periodBegin).slice(0, 10);
  const lines = [`Imported ${title} (${report.domain}, ${date})`];
  if (result.findings.length === 0) {
    lines.push(
      stats.fail === 0
        ? `${plural(stats.messages, "message")} — all passed`
        : `${plural(stats.messages, "message")} — ${formatNumber(stats.pass)} passed, ${formatNumber(stats.fail)} failed`,
    );
    return lines.join("\n");
  }
  lines.push(
    "",
    plural(stats.messages, "message"),
    `${formatNumber(stats.pass)} passed`,
    `${formatNumber(stats.fail)} failed`,
    "",
    ...renderFindings(result.findings),
  );
  return lines.join("\n");
}

function commandImport(
  db: Database,
  paths: DataPaths,
  inputs: string[],
): number {
  if (inputs.length === 0) {
    throw new UsageError("import needs at least one file or directory");
  }
  const missing = inputs.filter((input) => !existsSync(input));
  if (missing.length > 0) {
    throw new UsageError(`Not found: ${missing.join(", ")}`);
  }
  const files = collectFiles(inputs, options.recursive);
  if (files.length === 0) {
    throw new UsageError("No .xml, .gz, or .zip files found");
  }

  const results: ImportResult[] = [];
  const failures: { file: string; error: string }[] = [];
  let previousMultiline = false;
  const fail = (name: string, error: unknown): void => {
    if (
      !(error instanceof ReportError) &&
      !(error instanceof Error && "code" in error)
    ) {
      throw error;
    }
    failures.push({ file: name, error: error.message });
    if (!options.json) {
      process.stderr.write(`Not imported: ${name}: ${error.message}\n`);
    }
  };

  for (const file of files) {
    let sources: ReportSource[];
    try {
      sources = readReportSources(file);
    } catch (error) {
      fail(file, error);
      continue;
    }
    // Each report in a zip file is imported on its own, so one bad member does not block the others.
    for (const source of sources) {
      try {
        const result = importReport(db, source, {
          archiveDir: paths.archive,
          dataDir: paths.dataDir,
        });
        results.push(result);
        if (options.json) {
          continue;
        }
        if (result.status === "conflict") {
          process.stderr.write(
            `Conflict: ${source.name}: ${result.message ?? ""} — not imported\n`,
          );
        } else {
          // Separate multi-line blocks with a blank line; keep one-line results compact.
          const text = renderImport(result, paths);
          const multiline = text.includes("\n");
          if (results.length > 1 && (multiline || previousMultiline)) print("");
          previousMultiline = multiline;
          print(text);
        }
      } catch (error) {
        fail(source.name, error);
      }
    }
  }

  if (options.json) {
    printJson({
      database: paths.database,
      results: results.map((result) => ({
        file: result.file,
        status: result.status,
        reporter: result.report.reporter,
        reportId: result.report.reportId,
        domain: result.report.domain,
        periodBegin: result.report.periodBegin,
        periodEnd: result.report.periodEnd,
        archivePath: result.archivePath ?? null,
        message: result.message ?? null,
        ...result.stats,
        findings: result.findings,
      })),
      failures,
    });
  } else if (results.length + failures.length > 1) {
    const count = (status: ImportResult["status"]): number =>
      results.filter((result) => result.status === status).length;
    const parts = [
      `${formatNumber(count("imported"))} imported`,
      `${formatNumber(count("duplicate"))} already imported`,
    ];
    if (count("conflict") > 0)
      parts.push(`${formatNumber(count("conflict"))} conflicting`);
    if (failures.length > 0)
      parts.push(`${formatNumber(failures.length)} not imported`);
    print(
      `\n${plural(results.length + failures.length, "report")} in ${plural(files.length, "file")}: ${parts.join(", ")}`,
    );
  }
  return failures.length > 0 ||
    results.some((result) => result.status === "conflict")
    ? 1
    : 0;
}

// --- inspection ---------------------------------------------------------

function commandSummary(db: Database, paths: DataPaths): void {
  const days = positiveInteger(options.days, "days") ?? 30;
  const data = summary(db, days);
  if (options.json) {
    printJson({ database: paths.database, ...data });
    return;
  }
  print(
    [
      "DMARC database",
      "",
      pairs([
        ["Reports", formatNumber(data.reports)],
        ["Messages", formatNumber(data.messages)],
        ["Domains", formatNumber(data.domains)],
        ["Reporters", formatNumber(data.reporters)],
        ["Known senders", formatNumber(data.knownSenders)],
        [
          "Period",
          data.firstDate === null
            ? "-"
            : `${data.firstDate} — ${data.lastDate ?? "?"}`,
        ],
      ]),
      "",
      `Last ${days} days`,
      "",
      pairs([
        ["Reports", formatNumber(data.window.reports)],
        ["Pass", formatNumber(data.window.pass)],
        ["Fail", formatNumber(data.window.fail)],
        ["Unknown senders", formatNumber(data.window.unknownSenders)],
      ]),
      "",
      `Database: ${paths.database}`,
    ].join("\n"),
  );
}

function commandReports(db: Database): void {
  const limit = positiveInteger(options.limit, "limit");
  const rows = listReports(
    db,
    filterFromOptions(),
    limit ?? (options.days === undefined ? 50 : undefined),
  );
  printRows(
    [
      { header: "DATE", key: "date" },
      { header: "REPORTER", key: "reporter" },
      { header: "DOMAIN", key: "domain" },
      { header: "RECORDS", key: "records", align: "right" },
      { header: "MESSAGES", key: "messages", align: "right" },
      { header: "PASS", key: "pass", align: "right" },
      { header: "FAIL", key: "fail", align: "right" },
      { header: "REPORT ID", key: "report_id" },
    ],
    rows,
    "No reports.",
  );
}

function commandFailures(db: Database): void {
  printRows(
    [
      { header: "DATE", key: "report_date" },
      { header: "DOMAIN", key: "domain" },
      { header: "REPORTER", key: "reporter" },
      { header: "IP", key: "source_ip" },
      { header: "COUNT", key: "message_count", align: "right" },
      { header: "FROM", key: "header_from" },
      { header: "DKIM", key: "dkim_evaluation" },
      { header: "SPF", key: "spf_evaluation" },
      { header: "DISPOSITION", key: "disposition" },
      {
        header: "AUTH RESULTS",
        key: "dkim_auth",
        format: (value) => (value === null ? "no DKIM" : String(value)),
      },
    ],
    listFailures(db, filterFromOptions()),
    "No DMARC failures.",
  );
}

function commandUnknown(db: Database): void {
  const rows = listUnknown(db, filterFromOptions());
  printRows(
    [
      { header: "FIRST SEEN", key: "first_seen" },
      { header: "LAST SEEN", key: "last_seen" },
      { header: "IP", key: "source_ip" },
      { header: "COUNT", key: "message_count", align: "right" },
      { header: "FAIL", key: "fail", align: "right" },
      { header: "FROM", key: "header_from" },
      { header: "DKIM", key: "dkim_domains" },
      { header: "SPF", key: "spf_domains" },
      { header: "REGISTRY", key: "matched_senders" },
    ],
    rows,
    "No unknown senders.",
  );
  const registered = Number(
    db.get("SELECT count(*) AS n FROM senders")?.["n"] ?? 0,
  );
  if (!options.json && registered === 0 && rows.length > 0) {
    print(
      "\nThe sender registry is empty, so every sender is unknown. Add senders with: dmarc sender add",
    );
  }
}

function commandDaily(db: Database): void {
  printRows(
    [
      { header: "DATE", key: "date" },
      { header: "DOMAIN", key: "domain" },
      { header: "REPORTS", key: "reports", align: "right" },
      { header: "MESSAGES", key: "messages", align: "right" },
      { header: "PASS", key: "pass", align: "right" },
      { header: "FAIL", key: "fail", align: "right" },
      { header: "QUARANTINE", key: "quarantine", align: "right" },
      { header: "REJECT", key: "reject", align: "right" },
    ],
    listDaily(db, filterFromOptions()),
    "No data.",
  );
}

function commandDomains(db: Database): void {
  printRows(
    [
      { header: "DOMAIN", key: "domain" },
      { header: "FIRST SEEN", key: "first_seen" },
      { header: "LAST SEEN", key: "last_seen" },
      { header: "SEEN AS", key: "seen_as" },
    ],
    listDomains(db),
    "No domains.",
  );
}

function commandAnomalies(db: Database): void {
  const days = positiveInteger(options.days, "days") ?? 7;
  const rows = anomalies(db, days);
  if (options.json) {
    printJson(rows);
    return;
  }
  if (rows.length === 0) {
    print(`No anomalies in the last ${days} days.`);
    return;
  }
  print(
    table(
      [
        { header: "SIGNAL", key: "signal" },
        { header: "FIRST SEEN", key: "firstSeen" },
        { header: "SUBJECT", key: "subject" },
        { header: "DETAIL", key: "detail" },
      ],
      rows.map((row) => ({ ...row })),
    ),
  );
}

function renderCounted(title: string, entries: Counted[]): string[] {
  if (entries.length === 0) {
    return [];
  }
  const width = Math.max(...entries.map((entry) => entry.value.length));
  return [
    "",
    `${title}:`,
    ...entries.map(
      (entry) =>
        `  ${entry.value.padEnd(width)}   ${plural(entry.messages, "message")}`,
    ),
  ];
}

function commandInspect(db: Database, query: string): number {
  const data = inspectSender(db, query);
  if (options.json) {
    printJson(data);
    return data.records === 0 ? 1 : 0;
  }
  if (data.records === 0) {
    print(`No observations for ${query}.`);
    return 1;
  }
  const lines = [
    pairs([
      ["Sender", `${query} (${data.kind})`],
      ["First seen", data.firstSeen ?? "-"],
      ["Last seen", data.lastSeen ?? "-"],
      ["Messages", formatNumber(data.messages)],
      ["Records", formatNumber(data.records)],
    ]),
    "",
    "DMARC:",
    `  ${formatNumber(data.pass)} pass`,
    `  ${formatNumber(data.fail)} fail`,
  ];
  if (data.kind !== "ip")
    lines.push(...renderCounted("Source IPs", data.sourceIps));
  lines.push(
    ...renderCounted("Header-from", data.headerFrom),
    ...renderCounted("DKIM", data.dkim),
    ...renderCounted("SPF", data.spf),
    ...renderCounted("Policy domains", data.policyDomains),
    ...renderCounted("Reporters", data.reporters),
    ...renderCounted("Dispositions", data.dispositions),
  );
  lines.push("", "Registry:");
  if (data.registry.length === 0) {
    lines.push("  not matched by any registered sender");
  } else {
    lines.push(...renderCounted("", data.registry).slice(2));
  }
  print(lines.join("\n"));
  return 0;
}

// --- sender registry ----------------------------------------------------

function commandSender(db: Database, args: string[]): number {
  const [action, ...rest] = args;
  if (action === undefined) {
    throw new UsageError(
      "sender needs an IP address, CIDR range, domain, or one of: add, list, remove",
    );
  }

  if (action === "list") {
    const senders = listSenders(db);
    if (options.json) {
      printJson(senders);
    } else if (senders.length === 0) {
      print(
        "The sender registry is empty. Add senders with: dmarc sender add <name> --dkim-domain ...",
      );
    } else {
      const blocks = senders.map((sender) => {
        const lines = [
          `${sender.name} (${sender.status})${sender.notes === null ? "" : ` — ${sender.notes}`}`,
        ];
        if (sender.identifiers.length === 0) {
          lines.push("  no identifiers");
        } else {
          lines.push(
            table(
              [
                { header: "  TYPE", key: "type" },
                { header: "VALUE", key: "value" },
                { header: "FIRST SEEN", key: "firstSeen" },
                { header: "LAST SEEN", key: "lastSeen" },
                { header: "MESSAGES", key: "messages", align: "right" },
              ],
              sender.identifiers.map((identifier) => ({
                ...identifier,
                type: `  ${identifier.type}`,
              })),
            ),
          );
        }
        return lines.join("\n");
      });
      print(blocks.join("\n\n"));
    }
    return 0;
  }

  if (action === "add" || action === "remove") {
    const name = rest.join(" ").trim();
    if (name === "") {
      throw new UsageError(`sender ${action} needs a name`);
    }
    const identifiers = identifiersFromOptions();
    if (action === "remove") {
      const removed = removeSender(db, name, identifiers);
      print(
        identifiers.length === 0
          ? `Removed sender ${name}`
          : `Removed ${plural(removed, "identifier")} from ${name}`,
      );
      return 0;
    }
    if (options.status !== undefined && !isSenderStatus(options.status)) {
      throw new UsageError(
        `--status must be one of: ${SENDER_STATUSES.join(", ")}`,
      );
    }
    const result = addSender(db, name, {
      ...(options.status !== undefined && isSenderStatus(options.status)
        ? { status: options.status }
        : {}),
      ...(options.notes !== undefined ? { notes: options.notes } : {}),
      identifiers,
    });
    print(
      `${result.created ? "Added" : "Updated"} sender ${name} (${plural(result.added, "new identifier")})`,
    );
    return 0;
  }

  if (rest.length > 0) {
    throw new UsageError(
      "sender inspection takes one IP address, CIDR range, or domain",
    );
  }
  return commandInspect(db, action);
}

// --- main ---------------------------------------------------------------

function version(): string {
  const manifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  ) as { version?: string };
  return manifest.version ?? "unknown";
}

function main(): number {
  if (options.version) {
    print(version());
    return 0;
  }
  let [command, ...args] = positionals;
  if (options.help || command === undefined || command === "help") {
    print(HELP.trimEnd());
    return command === undefined && !options.help ? 1 : 0;
  }
  if (!COMMANDS.has(command)) {
    if (!existsSync(command)) {
      throw new UsageError(`Unknown command or file: ${command}`);
    }
    args = [command, ...args];
    command = "import";
  }

  const paths = resolvePaths(options["data-dir"]);

  if (command === "rebuild") {
    const result = rebuild(paths);
    if (options.json) {
      printJson(result);
    } else {
      print(
        [
          "Database rebuilt from the archive",
          "",
          pairs([
            ["Files", formatNumber(result.files)],
            ["Imported", formatNumber(result.imported)],
            ["Duplicates", formatNumber(result.duplicates)],
            ["Failed", formatNumber(result.failed.length)],
            ["Senders kept", formatNumber(result.senders)],
            ["Database", paths.database],
            ["Backup", result.backup ?? "-"],
          ]),
          ...result.failed.map(
            (failure) => `Failed: ${failure.file}: ${failure.error}`,
          ),
        ].join("\n"),
      );
    }
    return result.failed.length > 0 ? 1 : 0;
  }

  const db = new Database(paths.database);
  try {
    switch (command) {
      case "import":
        return commandImport(db, paths, args);
      case "summary":
        commandSummary(db, paths);
        return 0;
      case "reports":
        commandReports(db);
        return 0;
      case "failures":
        commandFailures(db);
        return 0;
      case "unknown":
        commandUnknown(db);
        return 0;
      case "daily":
        commandDaily(db);
        return 0;
      case "domains":
        commandDomains(db);
        return 0;
      case "anomalies":
        commandAnomalies(db);
        return 0;
      case "sender":
        return commandSender(db, args);
      default:
        throw new UsageError(`Unknown command: ${command}`);
    }
  } finally {
    db.close();
  }
}

try {
  process.exitCode = main();
} catch (error) {
  if (
    error instanceof UsageError ||
    error instanceof RegistryError ||
    error instanceof ReportError
  ) {
    process.stderr.write(`dmarc: ${error.message}\n`);
    process.exitCode = 2;
  } else {
    throw error;
  }
}
