import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  checkMechanism,
  combinedAlignment,
  domainsAlign,
} from "../src/alignment.ts";
import { Database } from "../src/db.ts";
import { importReport } from "../src/importer.ts";
import { listAlignment } from "../src/queries.ts";
import { SPOOF_REPORT, temporaryPaths } from "./helpers.ts";

const pass = (domain: string, scope?: string) => ({
  domain,
  result: "pass",
  ...(scope ? { scope } : {}),
});

test("strict alignment compares normalised exact domains, including IDNA", () => {
  assert.equal(
    domainsAlign("MAIL.Example.COM.", "mail.example.com", "s"),
    true,
  );
  assert.equal(domainsAlign("mail.example.com", "example.com", "s"), false);
  assert.equal(domainsAlign("bücher.de", "xn--bcher-kva.de", "s"), true);
  for (const bad of [
    null,
    "",
    "192.0.2.1",
    "http://example.com",
    "example.com/path",
    "x@example.com",
    "-bad.example.com",
    "a..example.com",
  ]) {
    assert.equal(domainsAlign(bad, "example.com", "s"), null);
  }
});

test("relaxed alignment uses multi-label suffixes, private suffixes, wildcard rules, and exceptions", () => {
  assert.equal(domainsAlign("a.example.co.uk", "b.example.co.uk", "r"), true);
  assert.equal(domainsAlign("a.example.co.uk", "other.co.uk", "r"), false);
  assert.equal(domainsAlign("a.example.com", "b.example.com", null), true);
  assert.equal(domainsAlign("notexample.com", "example.com", "r"), false);
  assert.equal(domainsAlign("co.uk", "co.uk", "r"), false);
  assert.equal(domainsAlign("a.github.io", "b.github.io", "r"), false);
  assert.equal(domainsAlign("mail.a.github.io", "a.github.io", "r"), true);
  assert.equal(domainsAlign("a.foo.ck", "b.foo.ck", "r"), false);
  assert.equal(domainsAlign("a.www.ck", "www.ck", "r"), true);
  assert.equal(domainsAlign("a.example.com", "example.com", "invalid"), null);
});

test("only authenticated passing identifiers count; any aligned signature is sufficient", () => {
  const failed = { domain: "example.com", result: "fail" };
  assert.equal(
    checkMechanism("example.com", "s", [failed, pass("evil.example")], "dkim")
      .result,
    "fail",
  );
  assert.equal(
    checkMechanism(
      "example.com",
      "s",
      [pass("evil.example"), pass("example.com")],
      "dkim",
    ).result,
    "pass",
  );
  assert.equal(
    checkMechanism(
      "example.com",
      "s",
      [{ domain: null, result: "pass" }, pass("example.com")],
      "dkim",
    ).result,
    "pass",
  );
  assert.equal(
    checkMechanism(
      "example.com",
      "s",
      [{ domain: null, result: "pass" }],
      "dkim",
    ).result,
    "unknown",
  );
  assert.equal(
    checkMechanism("example.com", "r", [], "dkim").result,
    "unknown",
  );
  assert.equal(
    checkMechanism(null, "r", [pass("example.com")], "dkim").result,
    "unknown",
  );
  assert.equal(
    checkMechanism("example.com", "broken", [pass("example.com")], "dkim")
      .result,
    "unknown",
  );
  assert.equal(
    checkMechanism(
      "example.com",
      "r",
      [{ domain: "example.com", result: null }],
      "dkim",
    ).result,
    "unknown",
  );
});

test("SPF uses MAIL FROM evidence and records assumptions for old reports", () => {
  assert.equal(
    checkMechanism("example.com", "s", [pass("example.com", "mfrom")], "spf")
      .result,
    "pass",
  );
  assert.equal(
    checkMechanism("example.com", "s", [pass("example.com", "helo")], "spf")
      .result,
    "unknown",
  );
  assert.equal(
    checkMechanism(
      "example.com",
      "s",
      [pass("other.example", "mfrom"), pass("example.com", "helo")],
      "spf",
    ).result,
    "fail",
  );
  const legacy = checkMechanism(
    "example.com",
    "r",
    [pass("example.com")],
    "spf",
  );
  assert.equal(legacy.result, "pass");
  assert.match(legacy.note ?? "", /assumed MAIL FROM/);
  assert.equal(combinedAlignment("pass", "unknown"), "pass");
  assert.equal(combinedAlignment("fail", "unknown"), "unknown");
  assert.equal(combinedAlignment("fail", "fail"), "fail");
});

test("lists mechanism mismatches even when overall DMARC agrees, without changing observations or archives", () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  // First row: receiver DKIM pass versus unaligned passing signatures, but SPF still passes.
  const xml = SPOOF_REPORT.replace(
    "<dkim><domain>mail.example.com</domain><selector>resend</selector><result>pass</result></dkim>",
    "<dkim><domain>unrelated.example.net</domain><selector>resend</selector><result>pass</result></dkim>",
  );
  try {
    const imported = importReport(
      db,
      {
        name: "fixture.xml",
        sourceFile: "fixture.xml",
        data: Buffer.from(xml),
      },
      { dataDir: paths.dataDir, archiveDir: paths.archive },
    );
    const tables = [
      "reports",
      "records",
      "dkim_results",
      "spf_results",
      "v_records",
    ];
    const snapshot = tables.map((table) => db.all(`SELECT * FROM ${table}`));
    const archive = join(paths.dataDir, imported.archivePath ?? "");
    const original = readFileSync(archive);
    db.db.exec("PRAGMA query_only = ON");
    const results = listAlignment(db, {});
    assert.equal(results.length, 1);
    assert.equal(results[0]?.dkim_recalculated, "fail");
    assert.equal(results[0]?.spf_recalculated, "pass");
    assert.equal(results[0]?.dmarc_recalculated, "pass");
    assert.equal(results[0]?.["dmarc_result"], "pass");
    assert.deepEqual(results[0]?.differences, ["dkim"]);
    assert.equal(listAlignment(db, {}, true).length, 2);
    assert.equal(listAlignment(db, { domain: "missing.example" }).length, 0);
    assert.equal(listAlignment(db, { reporter: "missing" }).length, 0);
    assert.equal(listAlignment(db, { days: 1 }).length, 0);
    assert.deepEqual(
      tables.map((table) => db.all(`SELECT * FROM ${table}`)),
      snapshot,
    );
    assert.deepEqual(readFileSync(archive), original);
    const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
    const json = execFileSync(
      process.execPath,
      [cli, "alignment", "--data-dir", paths.dataDir, "--json"],
      { encoding: "utf8" },
    );
    assert.equal((JSON.parse(json) as unknown[]).length, 1);
    const output = execFileSync(
      process.execPath,
      [cli, "alignment", "--data-dir", paths.dataDir],
      { encoding: "utf8" },
    );
    assert.match(output, /CHECKED DKIM/);
  } finally {
    db.close();
  }
});

test("missing receiver and authentication evidence remains unknown rather than a false mismatch", () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  const xml = SPOOF_REPORT.replaceAll(
    /<auth_results>[\s\S]*?<\/auth_results>/g,
    "",
  ).replaceAll(/<dkim>pass<\/dkim>/g, "");
  try {
    importReport(
      db,
      {
        name: "missing.xml",
        sourceFile: "missing.xml",
        data: Buffer.from(xml),
      },
      { dataDir: paths.dataDir, archiveDir: paths.archive },
    );
    assert.equal(listAlignment(db, {}).length, 0);
    const all = listAlignment(db, {}, true);
    assert.equal(all.length, 2);
    assert.ok(
      all.every(
        (row) =>
          row.dkim_recalculated === "unknown" &&
          row.spf_recalculated === "unknown",
      ),
    );
  } finally {
    db.close();
  }
});

test("stored strict and relaxed policies produce different checks and detect both directions of disagreement", () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  const relaxed = SPOOF_REPORT.replace(
    "<dkim><domain>mail.example.com</domain><selector>resend</selector><result>pass</result></dkim>",
    "<dkim><domain>x.mail.example.com</domain><selector>resend</selector><result>pass</result></dkim>",
  );
  const strict = relaxed
    .replace("test-spoof-0001", "strict-case")
    .replace("<adkim>r</adkim>", "<adkim>s</adkim>")
    .replace("<aspf>r</aspf>", "<aspf>s</aspf>");
  const receiverFail = relaxed
    .replace("test-spoof-0001", "receiver-fail")
    .replaceAll("<dkim>pass</dkim>", "<dkim>fail</dkim>")
    .replaceAll("<spf>pass</spf>", "<spf>fail</spf>");
  try {
    for (const [index, xml] of [relaxed, strict, receiverFail].entries())
      importReport(
        db,
        {
          name: `${index}.xml`,
          sourceFile: `${index}.xml`,
          data: Buffer.from(xml),
        },
        { dataDir: paths.dataDir, archiveDir: paths.archive },
      );
    const results = listAlignment(db, {});
    assert.equal(results.length, 2);
    const strictRow = results.find((row) => row["report_id"] === "strict-case");
    assert.deepEqual(strictRow?.differences, ["dkim", "spf"]);
    assert.equal(strictRow?.dmarc_recalculated, "fail");
    const failRow = results.find((row) => row["report_id"] === "receiver-fail");
    assert.equal(failRow?.dmarc_recalculated, "pass");
    assert.equal(failRow?.["dmarc_comparison_reported"], "fail");
  } finally {
    db.close();
  }
});
