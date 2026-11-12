import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { Database } from "../src/db.ts";
import {
  type GmailReader,
  gmailReader,
  ingestGmail,
  READONLY_SCOPE,
  reviewLink,
} from "../src/gmail.ts";
import { rebuild } from "../src/rebuild.ts";
import { buildZip, sampleFiles, temporaryPaths } from "./helpers.ts";

const account = "user@example.com";
const senders = ["noreply-dmarc-support@google.com"];
function reader(
  data: Buffer[],
  counters: { downloads: number },
  sender = senders[0],
): GmailReader {
  return {
    account,
    async *list() {
      yield "abc123";
      yield "abc123";
    },
    async message(id) {
      return {
        id,
        payload: {
          headers: [{ name: "From", value: `Reports <${sender}>` }],
          parts: data.map((_, i) => ({
            filename: "report.zip",
            partId: String(i),
            body: { attachmentId: String(i) },
          })),
        },
      };
    },
    async attachment(_id, attachmentId) {
      counters.downloads++;
      return data[Number(attachmentId)]?.toString("base64url") ?? "";
    },
  };
}

test("partial failure never supplies a review link; retry skips successful attachments; rebuild retains review", async () => {
  const paths = temporaryPaths();
  let db = new Database(paths.database);
  const data = [readFileSync(sampleFiles()[0] ?? ""), Buffer.from("invalid")];
  const counters = { downloads: 0 };
  const mail = reader(data, counters);
  try {
    const first = await ingestGmail(db, paths, mail, senders);
    assert.equal(first[0]?.status, "failed");
    assert.equal(first[0]?.link, undefined);
    assert.equal(
      (await ingestGmail(db, paths, mail, senders, false, true)).length,
      0,
    );
    data[1] = readFileSync(sampleFiles()[1] ?? "");
    const retry = await ingestGmail(db, paths, mail, senders);
    assert.equal(retry[0]?.status, "complete");
    assert.equal(counters.downloads, 3);
    await ingestGmail(db, paths, mail, senders);
    assert.equal(counters.downloads, 3);
    assert.equal(db.all("SELECT * FROM reports").length, 2);
    db.close();
    rebuild(paths);
    db = new Database(paths.database);
    assert.equal(
      (await ingestGmail(db, paths, mail, senders, false, true))[0]?.link,
      reviewLink(account, "abc123"),
    );
    db.run("DELETE FROM reports");
    assert.equal(
      (await ingestGmail(db, paths, mail, senders, false, true)).length,
      0,
    );
  } finally {
    db.close();
  }
});

test("dry run validates nested compressed reports without archive or ledger writes", async () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  try {
    const before = readdirSync(paths.dataDir);
    const zip = buildZip([
      { name: "report.xml", content: readFileSync(sampleFiles()[0] ?? "") },
    ]);
    const results = await ingestGmail(
      db,
      paths,
      reader([zip], { downloads: 0 }),
      senders,
      true,
    );
    assert.equal(results[0]?.status, "validated");
    assert.equal(results[0]?.link, undefined);
    assert.equal(db.all("SELECT * FROM reports").length, 0);
    assert.deepEqual(readdirSync(paths.dataDir), before);
    assert.equal(existsSync(join(paths.dataDir, "gmail.sqlite")), false);
    assert.equal(existsSync(paths.archive), false);
  } finally {
    db.close();
  }
});

test("sender mismatch prevents downloads; conflicting report blocks review", async () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  const counters = { downloads: 0 };
  const xml = readFileSync(sampleFiles()[0] ?? "");
  try {
    assert.equal(
      (
        await ingestGmail(
          db,
          paths,
          reader([xml], counters, "spoof@example.com"),
          senders,
        )
      )[0]?.status,
      "failed",
    );
    assert.equal(counters.downloads, 0);
    await ingestGmail(db, paths, reader([xml], counters), senders);
    const changed = Buffer.from(
      xml.toString().replace("<count>1</count>", "<count>2</count>"),
    );
    const other = reader([changed], counters);
    other.list = async function* () {
      yield "def456";
    };
    const result = await ingestGmail(db, paths, other, senders);
    assert.equal(result[0]?.status, "failed");
    assert.equal(result[0]?.link, undefined);
  } finally {
    db.close();
  }
});

test("transport only reads Gmail, paginates, and rejects broader OAuth scopes", async (t) => {
  const calls: { url: string; method: string }[] = [];
  let broad = false;
  t.mock.method(
    globalThis,
    "fetch",
    async (input: string, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, method: init?.method ?? "GET" });
      if (url === "https://oauth2.googleapis.com/token")
        return Response.json({
          access_token: "example",
          scope: broad ? "https://mail.google.com/" : READONLY_SCOPE,
        });
      if (url.endsWith("profile"))
        return Response.json({ emailAddress: account });
      if (url.includes("pageToken="))
        return Response.json({ messages: [{ id: "def456" }] });
      return Response.json({
        messages: [{ id: "abc123" }],
        nextPageToken: "next",
      });
    },
  );
  const config = {
    account,
    senders: senders as string[],
    clientId: "example",
    clientSecret: "example",
    refreshToken: "example",
  };
  const mail = await gmailReader(config);
  const ids = [];
  for await (const id of mail.list(config.senders)) ids.push(id);
  assert.deepEqual(ids, ["abc123", "def456"]);
  assert.ok(
    calls
      .filter((call) => call.url.includes("gmail.googleapis.com"))
      .every((call) => call.method === "GET"),
  );
  broad = true;
  await assert.rejects(gmailReader(config), /exactly gmail.readonly/);
});

test("one bad zip member blocks review, and recovery does not duplicate earlier members", async () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  const good = readFileSync(sampleFiles()[0] ?? "");
  const data = [
    buildZip([
      { name: "one.xml", content: good },
      { name: "two.xml", content: Buffer.from("broken") },
    ]),
  ];
  const mail = reader(data, { downloads: 0 });
  try {
    assert.equal(
      (await ingestGmail(db, paths, mail, senders))[0]?.status,
      "failed",
    );
    assert.equal(db.all("SELECT * FROM reports").length, 1);
    data[0] = buildZip([
      { name: "one.xml", content: good },
      { name: "two.xml", content: readFileSync(sampleFiles()[1] ?? "") },
    ]);
    assert.equal(
      (await ingestGmail(db, paths, mail, senders))[0]?.status,
      "complete",
    );
    assert.equal(db.all("SELECT * FROM reports").length, 2);
  } finally {
    db.close();
  }
});

test("dry run detects conflicting identities within the same run", async () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  const good = readFileSync(sampleFiles()[0] ?? "");
  const changed = Buffer.from(
    good.toString().replace("<count>1</count>", "<count>2</count>"),
  );
  try {
    const result = await ingestGmail(
      db,
      paths,
      reader([good, changed], { downloads: 0 }),
      senders,
      true,
    );
    assert.equal(result[0]?.status, "failed");
    assert.match(result[0]?.error ?? "", /conflict/);
    assert.equal(db.all("SELECT * FROM reports").length, 0);
  } finally {
    db.close();
  }
});

test("oversized or unrelated attachments block completion", async () => {
  const paths = temporaryPaths();
  const db = new Database(paths.database);
  const mail = reader([], { downloads: 0 });
  mail.message = async (id) => ({
    id,
    payload: {
      headers: [{ name: "From", value: senders[0] ?? "" }],
      parts: [
        {
          filename: "report.gz",
          body: { size: 65 * 1024 * 1024, attachmentId: "large" },
        },
      ],
    },
  });
  mail.attachment = async () => {
    throw new Error("Should not download");
  };
  try {
    const result = await ingestGmail(db, paths, mail, senders);
    assert.match(result[0]?.error ?? "", /size limit/);
    assert.equal(result[0]?.link, undefined);
  } finally {
    db.close();
  }
});
