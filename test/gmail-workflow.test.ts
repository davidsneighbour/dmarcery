import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { credentialsPath, loadMailAccounts } from "../src/config.ts";
import { Database } from "../src/db.ts";
import type { GmailReader } from "../src/gmail.ts";
import { importMailAccounts } from "../src/gmail-workflow.ts";
import { sampleFiles, temporaryPaths, writeFixture } from "./helpers.ts";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const content = `[gmail]
senders = ["reports@example.com"]
[[gmail.accounts]]
address = "one@example.com"
[[gmail.accounts]]
address = "two@example.com"
`;

function setup() {
  const paths = temporaryPaths();
  const config = writeFixture(paths.dataDir, "mail.toml", content);
  return { paths, config, accounts: loadMailAccounts(config, paths.dataDir) };
}

function mailbox(account: string, onDownload: () => void): GmailReader {
  return {
    account,
    async *list(senders) {
      assert.deepEqual(senders, ["reports@example.com"]);
      yield "abc123";
    },
    async message(id) {
      return {
        id,
        payload: {
          headers: [{ name: "From", value: "reports@example.com" }],
          parts: [
            { filename: "report.xml", body: { attachmentId: "attachment" } },
          ],
        },
      };
    },
    async attachment() {
      onDownload();
      return readFileSync(sampleFiles()[0] ?? "").toString("base64url");
    },
  };
}

test("two mailboxes may share message IDs and report XML; tracking and offline CLI review stay account-specific", async () => {
  const { paths, config, accounts } = setup();
  const db = new Database(paths.database);
  let downloads = 0;
  try {
    const create = async (account: (typeof accounts)[number]) =>
      mailbox(account.address, () => downloads++);
    const first = await importMailAccounts(
      db,
      paths,
      accounts,
      { dryRun: false, review: false },
      create,
    );
    assert.equal(first.length, 2);
    assert.ok(
      first.every((outcome) => outcome.messages[0]?.status === "complete"),
    );
    assert.notEqual(first[0]?.messages[0]?.link, first[1]?.messages[0]?.link);
    assert.equal(downloads, 2);
    assert.equal(db.all("SELECT * FROM reports").length, 1);
    await importMailAccounts(
      db,
      paths,
      accounts,
      { dryRun: false, review: false },
      create,
    );
    assert.equal(downloads, 2);
    // Offline review needs TOML addresses only, not credentials or access to Google.
    assert.equal(
      existsSync(credentialsPath(paths.dataDir, "one@example.com")),
      false,
    );
    const output = execFileSync(
      process.execPath,
      [
        cli,
        "import",
        "--review",
        "--config",
        config,
        "--data-dir",
        paths.dataDir,
        "--json",
      ],
      { encoding: "utf8" },
    );
    const reviewed = JSON.parse(output) as typeof first;
    assert.equal(reviewed.length, 2);
    assert.ok(reviewed.every((outcome) => outcome.messages.length === 1));
    const selected = execFileSync(
      process.execPath,
      [
        cli,
        "import",
        "--review",
        "--account",
        "two@example.com",
        "--config",
        config,
        "--data-dir",
        paths.dataDir,
        "--json",
      ],
      { encoding: "utf8" },
    );
    assert.deepEqual(
      (JSON.parse(selected) as typeof first).map((outcome) => outcome.account),
      ["two@example.com"],
    );
  } finally {
    db.close();
  }
});

test("one mailbox failure does not stop the next mailbox; failures identify the account", async () => {
  const { paths, accounts } = setup();
  const db = new Database(paths.database);
  try {
    const outcomes = await importMailAccounts(
      db,
      paths,
      accounts,
      { dryRun: false, review: false },
      async (account) => {
        if (account.address === "one@example.com")
          throw new Error("Authorisation failed");
        return mailbox(account.address, () => {});
      },
    );
    assert.equal(outcomes[0]?.error, "Authorisation failed");
    assert.equal(outcomes[1]?.messages[0]?.status, "complete");
    const missing = await importMailAccounts(db, paths, accounts, {
      dryRun: false,
      review: false,
    });
    assert.ok(
      missing.every((outcome) =>
        outcome.error?.includes("gmail-auth --account"),
      ),
    );
  } finally {
    db.close();
  }
});

test("CLI dry run with missing mailbox tokens reports both failures without creating local state", () => {
  const { paths, config } = setup();
  const dataDir = join(paths.dataDir, "empty");
  const result = spawnSync(
    process.execPath,
    [
      cli,
      "import",
      "--dry-run",
      "--config",
      config,
      "--data-dir",
      dataDir,
      "--json",
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 1);
  const outcomes = JSON.parse(result.stdout) as {
    account: string;
    error?: string;
  }[];
  assert.equal(outcomes.length, 2);
  assert.ok(outcomes.every((outcome) => outcome.error));
  assert.equal(existsSync(dataDir), false);
  assert.deepEqual(readdirSync(paths.dataDir), ["mail.toml"]);
});
