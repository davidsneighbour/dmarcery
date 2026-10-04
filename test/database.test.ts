import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { Database } from "../src/db.ts";
import { importFile } from "../src/importer.ts";
import {
  anomalies,
  inspectSender,
  listFailures,
  listUnknown,
  summary,
} from "../src/queries.ts";
import { rebuild } from "../src/rebuild.ts";
import { addSender, listSenders, removeSender } from "../src/registry.ts";
import {
  SPOOF_REPORT,
  sampleFiles,
  temporaryPaths,
  writeFixture,
} from "./helpers.ts";

function setup() {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  const options = { archiveDir: paths.archive, dataDir: paths.dataDir };
  return { paths, db, options };
}

const count = (db: Database, table: string): number =>
  Number(db.get(`SELECT count(*) AS n FROM ${table}`)?.["n"]);

describe("import", () => {
  it("imports the sample reports idempotently", () => {
    const { db, options, paths } = setup();
    const first = sampleFiles().flatMap((file) =>
      importFile(db, file, options),
    );
    assert.deepEqual(
      first.map((result) => result.status),
      ["imported", "imported", "imported", "imported"],
    );
    const tables = ["reports", "records", "dkim_results", "spf_results"].map(
      (table) => count(db, table),
    );
    assert.deepEqual(tables, [4, 5, 10, 5]);

    const second = sampleFiles().flatMap((file) =>
      importFile(db, file, options),
    );
    assert.ok(second.every((result) => result.status === "duplicate"));
    assert.deepEqual(
      ["reports", "records", "dkim_results", "spf_results"].map((table) =>
        count(db, table),
      ),
      tables,
    );

    const totals = summary(db, 100_000);
    assert.equal(totals.messages, 6);
    assert.equal(totals.window.pass, 6);
    assert.equal(totals.window.fail, 0);

    // The archive holds the original bytes, read-only.
    const archived = join(paths.dataDir, first[0]?.archivePath ?? "");
    assert.equal(
      readFileSync(archived, "utf8"),
      readFileSync(sampleFiles()[0] ?? "", "utf8"),
    );
    assert.equal(statSync(archived).mode & 0o222, 0);
    db.close();
  });

  it("reports a conflict when a report ID returns with different content", () => {
    const { db, options } = setup();
    const directory = mkdtempSync(join(tmpdir(), "dmarcery-fixture-"));
    importFile(db, writeFixture(directory, "a.xml", SPOOF_REPORT), options);
    const changed = SPOOF_REPORT.replace(
      "<count>79</count>",
      "<count>80</count>",
    );
    const [result] = importFile(
      db,
      writeFixture(directory, "b.xml", changed),
      options,
    );
    assert.equal(result?.status, "conflict");
    assert.equal(count(db, "reports"), 1);
    db.close();
  });

  it("finds new identifiers and DMARC failures", () => {
    const { db, options } = setup();
    for (const file of sampleFiles()) importFile(db, file, options);
    const directory = mkdtempSync(join(tmpdir(), "dmarcery-fixture-"));
    const [result] = importFile(
      db,
      writeFixture(directory, "spoof.xml", SPOOF_REPORT),
      options,
    );
    assert.ok(result);

    const kinds = result.findings.map(
      (finding) => `${finding.kind}:${finding.value}`,
    );
    assert.ok(kinds.includes("new_source_ip:2001:db8::17"));
    assert.ok(kinds.includes("new_network:2001:db8:0::/48"));
    assert.ok(kinds.includes("new_header_from:example.com"));
    assert.ok(kinds.includes("new_spf_domain:spoof.test"));
    assert.ok(kinds.includes("dmarc_failure:2001:db8::17"));
    assert.ok(
      !kinds.some((kind) => kind.includes("192.0.2.52")),
      "known IP is not new",
    );
    assert.equal(result.stats.fail, 3);
    assert.equal(result.stats.pass, 79);

    assert.equal(count(db, "policy_reasons"), 2);
    const failures = listFailures(db, {});
    assert.equal(failures.length, 1);
    assert.equal(failures[0]?.["disposition"], "reject");
    db.close();
  });
});

describe("sender registry", () => {
  it("separates known from unknown senders without touching observations", () => {
    const { db, options } = setup();
    for (const file of sampleFiles()) importFile(db, file, options);
    const directory = mkdtempSync(join(tmpdir(), "dmarcery-fixture-"));
    importFile(db, writeFixture(directory, "spoof.xml", SPOOF_REPORT), options);
    const before = count(db, "records");

    assert.equal(listUnknown(db, {}).length, 4);
    addSender(db, "Resend", {
      status: "known",
      identifiers: [
        { type: "dkim_domain", value: "mail.example.com" },
        { type: "spf_domain", value: "bounce.mail.example.com" },
      ],
    });

    // The spoofed record carries a failing signature for the Resend domain; it must stay unknown.
    const unknown = listUnknown(db, {});
    assert.deepEqual(
      unknown.map((row) => row["source_ip"]),
      ["2001:db8::17"],
    );
    assert.equal(count(db, "records"), before);

    const resend = listSenders(db)[0];
    assert.equal(
      resend?.identifiers.find(
        (identifier) => identifier.type === "dkim_domain",
      )?.messages,
      85,
    );

    const inspection = inspectSender(db, "192.0.2.52");
    assert.equal(inspection.messages, 81);
    assert.equal(inspection.registry[0]?.messages, 81);

    // Retired senders still count as unknown, with the match shown.
    addSender(db, "Old relay", {
      status: "retired",
      identifiers: [{ type: "source_cidr", value: "2001:db8::/32" }],
    });
    assert.match(
      String(listUnknown(db, {})[0]?.["matched_senders"]),
      /Old relay \(retired\)/,
    );

    assert.equal(removeSender(db, "Old relay", []), 1);
    assert.equal(listSenders(db).length, 1);
    db.close();
  });

  it("reports anomalies inside the window", () => {
    const { db, options } = setup();
    for (const file of sampleFiles()) importFile(db, file, options);
    const now = Date.UTC(2026, 9, 2, 12); // 2026-10-02 12:00 UTC
    const signals = anomalies(db, 2, now).map(
      (anomaly) => `${anomaly.signal}:${anomaly.subject}`,
    );
    assert.ok(signals.includes("new source IP:192.0.2.55"));
    assert.ok(signals.includes("new source IP:192.0.2.58"));
    assert.ok(!signals.includes("new source IP:192.0.2.52"));
    db.close();
  });
});

describe("rebuild", () => {
  it("recreates the database from the archive and keeps the registry", () => {
    const { db, options, paths } = setup();
    for (const file of sampleFiles()) importFile(db, file, options);
    addSender(db, "Resend", {
      identifiers: [{ type: "dkim_selector", value: "resend" }],
    });
    db.close();

    const result = rebuild(paths);
    assert.equal(result.imported, 4);
    assert.equal(result.senders, 1);
    assert.equal(result.failed.length, 0);

    const fresh = new Database(paths.database);
    assert.equal(count(fresh, "records"), 5);
    assert.equal(listSenders(fresh)[0]?.identifiers[0]?.messages, 6);
    assert.ok(
      fresh
        .all("SELECT source_file FROM reports")
        .every((row) =>
          String(row["source_file"]).startsWith("receiver.example!"),
        ),
      "original file names survive the rebuild",
    );
    fresh.close();
  });
});
