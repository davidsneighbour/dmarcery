import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { cidrRange, ipKey, networkOf } from "../src/ip.ts";
import { parseReport, ReportError } from "../src/parse.ts";
import { sampleFiles, SPOOF_REPORT } from "./helpers.ts";

describe("ip", () => {
  it("maps IPv4 into the IPv6 key space", () => {
    assert.equal(ipKey("192.0.2.52"), "00000000000000000000ffffc0000234");
    assert.equal(ipKey("::ffff:192.0.2.52"), ipKey("192.0.2.52"));
  });

  it("normalises IPv6 notation", () => {
    assert.equal(ipKey("2001:DB8::17"), "20010db8000000000000000000000017");
    assert.equal(ipKey("2001:db8:0:0:0:0:0:17"), ipKey("2001:db8::17"));
    assert.equal(ipKey("not-an-ip"), null);
  });

  it("calculates CIDR ranges", () => {
    const range = cidrRange("192.0.2.0/24");
    assert.ok(range);
    const inside = ipKey("192.0.2.255") ?? "";
    const outside = ipKey("192.0.3.0") ?? "";
    assert.ok(inside >= range.start && inside <= range.end);
    assert.ok(outside > range.end);
    assert.equal(cidrRange("10.0.0.0/33"), null);
  });

  it("derives source networks", () => {
    assert.equal(networkOf("192.0.2.52"), "192.0.2.0/24");
    assert.equal(networkOf("2001:db8:1:2::1"), "2001:db8:1::/48");
  });
});

describe("parseReport", () => {
  it("parses every sample report", () => {
    for (const file of sampleFiles()) {
      const report = parseReport(readFileSync(file, "utf8"));
      assert.equal(report.reporter, "receiver.example");
      assert.equal(report.domain, "example.com");
      assert.equal(report.policy.p, "reject");
      assert.ok(report.records.length >= 1);
      for (const record of report.records) {
        assert.equal(record.dkim.length, 2, "both DKIM signatures are kept");
        assert.equal(record.spf.length, 1);
      }
    }
  });

  it("keeps report IDs as exact strings", () => {
    const file = sampleFiles().find((name) => name.includes("1790812800"));
    assert.ok(file);
    assert.equal(parseReport(readFileSync(file, "utf8")).reportId, "12172077135528107070");
  });

  it("parses namespaces, errors, reasons, and optional fields", () => {
    const report = parseReport(SPOOF_REPORT);
    assert.equal(report.version, null);
    assert.deepEqual(report.errors, ["Example error text"]);
    assert.equal(report.policy.fo, "1");
    const spoof = report.records[1];
    assert.ok(spoof);
    assert.equal(spoof.disposition, "reject");
    assert.deepEqual(spoof.reasons, [
      { type: "local_policy", comment: "first" },
      { type: "other", comment: null },
    ]);
    assert.equal(spoof.envelopeFrom, "spoof.test");
    assert.equal(spoof.dkim[0]?.humanResult, "bad signature");
  });

  it("rejects files that are not DMARC aggregate reports", () => {
    assert.throws(() => parseReport("<html><body/></html>"), ReportError);
    assert.throws(() => parseReport("<feedback><report_metadata/></feedback>"), ReportError);
    assert.throws(() => parseReport("<feedback><unclosed></feedback>"), ReportError);
    assert.throws(() => parseReport(SPOOF_REPORT.replace("<count>3</count>", "<count>x</count>")), ReportError);
  });
});
