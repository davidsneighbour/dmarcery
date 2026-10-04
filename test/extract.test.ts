import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { describe, it } from "node:test";
import { gzipSync } from "node:zlib";
import { Database } from "../src/db.ts";
import { detectFormat, readReportSources } from "../src/extract.ts";
import { collectFiles, importFile } from "../src/importer.ts";
import { ReportError } from "../src/parse.ts";
import { buildZip, sampleFiles, temporaryPaths, writeFixture } from "./helpers.ts";

function setup() {
  const paths = temporaryPaths();
  return {
    db: new Database(paths.database),
    options: { archiveDir: paths.archive, dataDir: paths.dataDir },
    directory: mkdtempSync(join(tmpdir(), "dmarcery-fixture-")),
  };
}

const [sampleA = "", sampleB = ""] = sampleFiles();

describe("compressed reports", () => {
  it("detects formats from content", () => {
    assert.equal(detectFormat(readFileSync(sampleA)), "xml");
    assert.equal(detectFormat(gzipSync("x")), "gzip");
    assert.equal(detectFormat(buildZip([{ name: "a.xml", content: Buffer.from("x") }])), "zip");
  });

  it("imports a gzip report and treats the same XML as one report", () => {
    const { db, options, directory } = setup();
    const gz = writeFixture(directory, `${basename(sampleA)}.gz`, gzipSync(readFileSync(sampleA)));
    const [fromGzip] = importFile(db, gz, options);
    assert.equal(fromGzip?.status, "imported");
    const [fromXml] = importFile(db, sampleA, options);
    assert.equal(fromXml?.status, "duplicate");
    assert.equal(db.get("SELECT source_file FROM reports")?.["source_file"], `${basename(sampleA)}.gz`);
    db.close();
  });

  it("imports every XML member of a zip file and ignores other members", () => {
    const { db, options, directory } = setup();
    const zip = writeFixture(
      directory,
      "reports.zip",
      buildZip([
        { name: "folder/a.xml", content: readFileSync(sampleA) },
        { name: "b.xml", content: readFileSync(sampleB) },
        { name: "readme.txt", content: Buffer.from("not a report") },
      ]),
    );
    const results = importFile(db, zip, options);
    assert.deepEqual(
      results.map((result) => result.status),
      ["imported", "imported"],
    );
    assert.deepEqual(
      db.all("SELECT source_file FROM reports ORDER BY id").map((row) => row["source_file"]),
      ["reports.zip:a.xml", "reports.zip:b.xml"],
    );
    db.close();
  });

  it("rejects archives that are corrupt, empty, or larger than declared", () => {
    const { directory } = setup();
    const lying = writeFixture(
      directory,
      "bomb.zip",
      buildZip([{ name: "a.xml", content: Buffer.alloc(100_000, 0x20), declaredSize: 100 }]),
    );
    assert.throws(() => readReportSources(lying), ReportError);
    const empty = writeFixture(directory, "empty.zip", buildZip([{ name: "a.txt", content: Buffer.from("x") }]));
    assert.throws(() => readReportSources(empty), /No \.xml report/);
    const broken = writeFixture(directory, "broken.zip", buildZip([{ name: "a.xml", content: Buffer.from("x") }]).subarray(0, 40));
    assert.throws(() => readReportSources(broken), ReportError);
    const badGzip = writeFixture(directory, "bad.xml.gz", gzipSync("<feedback/>").subarray(0, 12));
    assert.throws(() => readReportSources(badGzip), ReportError);
  });

  it("collects .xml, .gz, and .zip files from directories", () => {
    const { directory } = setup();
    for (const name of ["a.xml", "b.xml.gz", "c.ZIP", "d.txt"]) writeFixture(directory, name, "x");
    assert.deepEqual(
      collectFiles([directory], false).map((file) => basename(file)),
      ["a.xml", "b.xml.gz", "c.ZIP"],
    );
  });
});
