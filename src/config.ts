import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { parse } from "smol-toml";

export class ConfigError extends Error {
  override name = "ConfigError";
}

export interface MailAccount {
  address: string;
  senders: string[];
  clientFile: string;
  credentialsFile: string;
}

export const DEFAULT_CONFIG = join(homedir(), ".config", "dmarcery.toml");
export const DEFAULT_CLIENT = join(
  homedir(),
  ".msgvault",
  "client_secret.json",
);

function table(
  value: unknown,
  name: string,
  keys: string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new ConfigError(`${name} must be a TOML table`);
  const result = value as Record<string, unknown>;
  for (const key of Object.keys(result))
    if (!keys.includes(key))
      throw new ConfigError(`Unknown ${name} option: ${key}`);
  return result;
}

export function email(value: unknown, name: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$/.test(value)
  )
    throw new ConfigError(`${name} must be a plain email address`);
  return value.toLowerCase();
}

function senderList(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || !value.length)
    throw new ConfigError(`${name} needs at least one sender address`);
  return [...new Set(value.map((item) => email(item, name)))];
}

function configPath(value: unknown, base: string, name: string): string {
  if (typeof value !== "string" || !value.trim())
    throw new ConfigError(`${name} must be a non-empty path`);
  if (value === "~") return homedir();
  if (value.startsWith("~/")) return join(homedir(), value.slice(2));
  return isAbsolute(value) ? value : resolve(base, value);
}

export function credentialsPath(dataDir: string, address: string): string {
  const key = createHash("sha256").update(address.toLowerCase()).digest("hex");
  return join(dataDir, "gmail-credentials", `${key}.json`);
}

/** Settings contain addresses and client paths; refresh tokens are stored separately. */
export function loadMailAccounts(
  path: string,
  dataDir: string,
  selected?: string,
): MailAccount[] {
  let parsed: unknown;
  try {
    parsed = parse(readFileSync(path, "utf8"));
  } catch {
    throw new ConfigError(
      `Cannot read valid TOML from ${path}; see documentation/gmail.md for the configuration format`,
    );
  }
  const root = table(parsed, "configuration", ["gmail"]);
  const gmail = table(root["gmail"], "gmail", [
    "client_file",
    "senders",
    "accounts",
  ]);
  const base = dirname(resolve(path));
  const defaultClient =
    gmail["client_file"] === undefined
      ? DEFAULT_CLIENT
      : configPath(gmail["client_file"], base, "gmail.client_file");
  const defaultSenders =
    gmail["senders"] === undefined
      ? undefined
      : senderList(gmail["senders"], "gmail.senders");
  const entries = gmail["accounts"];
  if (!Array.isArray(entries) || !entries.length)
    throw new ConfigError("Configure at least one [[gmail.accounts]] table");
  const seen = new Set<string>();
  const accounts = entries.map((entry): MailAccount => {
    const account = table(entry, "gmail.accounts", [
      "address",
      "senders",
      "client_file",
    ]);
    const address = email(account["address"], "gmail.accounts.address");
    if (seen.has(address))
      throw new ConfigError(`Duplicate Gmail account: ${address}`);
    seen.add(address);
    const senders =
      account["senders"] === undefined
        ? defaultSenders
        : senderList(account["senders"], `Senders for ${address}`);
    if (!senders)
      throw new ConfigError(
        `Configure senders for ${address} or gmail.senders`,
      );
    return {
      address,
      senders,
      clientFile:
        account["client_file"] === undefined
          ? defaultClient
          : configPath(
              account["client_file"],
              base,
              "gmail.accounts.client_file",
            ),
      credentialsFile: credentialsPath(dataDir, address),
    };
  });
  if (!selected) return accounts;
  const address = email(selected, "--account");
  const matches = accounts.filter((account) => account.address === address);
  if (!matches.length)
    throw new ConfigError(`Account is not configured: ${address}`);
  return matches;
}
