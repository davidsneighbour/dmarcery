import assert from "node:assert/strict";
import { homedir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  credentialsPath,
  DEFAULT_CONFIG,
  loadMailAccounts,
} from "../src/config.ts";
import { temporaryPaths, writeFixture } from "./helpers.ts";

function settings(content: string) {
  const paths = temporaryPaths();
  const config = writeFixture(paths.dataDir, "settings.toml", content);
  return { paths, config };
}

const example = `[gmail]
client_file = "~/client.json"
senders = ["reports@example.com", "REPORTS@example.com"]

[[gmail.accounts]]
address = "ONE@example.com"

[[gmail.accounts]]
address = "two@example.com"
senders = ["other@example.com"]
client_file = "local-client.json"
`;

test("TOML loads several mailboxes with inherited settings, overrides, and separate token files", () => {
  const { paths, config } = settings(example);
  const accounts = loadMailAccounts(config, paths.dataDir);
  assert.equal(DEFAULT_CONFIG, join(homedir(), ".config", "dmarcery.toml"));
  assert.equal(accounts.length, 2);
  assert.deepEqual(accounts[0]?.senders, ["reports@example.com"]);
  assert.deepEqual(accounts[1]?.senders, ["other@example.com"]);
  assert.equal(accounts[0]?.address, "one@example.com");
  assert.equal(accounts[0]?.clientFile, join(homedir(), "client.json"));
  assert.equal(
    accounts[1]?.clientFile,
    join(paths.dataDir, "local-client.json"),
  );
  assert.notEqual(accounts[0]?.credentialsFile, accounts[1]?.credentialsFile);
  assert.equal(
    credentialsPath(paths.dataDir, "ONE@example.com"),
    accounts[0]?.credentialsFile,
  );
  assert.deepEqual(loadMailAccounts(config, paths.dataDir, "TWO@example.com"), [
    accounts[1],
  ]);
  assert.throws(
    () => loadMailAccounts(config, paths.dataDir, "missing@example.com"),
    /not configured/,
  );
});

test("TOML rejects duplicate accounts, malformed settings, empty senders, and misspelt options", () => {
  const invalid = [
    "[gmail",
    "",
    "[gmail]\naccounts=[]",
    example.replace("two@example.com", "one@example.com"),
    example.replace('senders = ["other@example.com"]', "senders = []"),
    example.replace('address = "two@example.com"', 'address = "from:bad"'),
    example.replace("client_file", "client_files"),
    example.replace(
      'senders = ["reports@example.com", "REPORTS@example.com"]',
      'senders = "reports@example.com"',
    ),
    '[gmail]\n[[gmail.accounts]]\naddress="one@example.com"',
    example.replace('client_file = "~/client.json"', "client_file = 42"),
  ];
  for (const content of invalid) {
    const { paths, config } = settings(content);
    assert.throws(() => loadMailAccounts(config, paths.dataDir));
  }
});
