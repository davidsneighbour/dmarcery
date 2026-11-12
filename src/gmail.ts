import { createHash } from "node:crypto";
import { chmodSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Database } from "./db.ts";
import { MAX_REPORT_BYTES, reportSourcesFromBuffer } from "./extract.ts";
import { importReport } from "./importer.ts";
import { parseReport } from "./parse.ts";
import type { DataPaths } from "./paths.ts";

export const READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
interface Config {
  account: string;
  senders: string[];
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}
export interface Part {
  partId?: string;
  filename?: string;
  headers?: { name: string; value: string }[];
  body?: { attachmentId?: string; data?: string; size?: number };
  parts?: Part[];
}
interface Message {
  id: string;
  payload?: Part;
}
export interface GmailReader {
  account: string;
  list(senders: string[]): AsyncIterable<string>;
  message(id: string): Promise<Message>;
  attachment(id: string, attachmentId: string): Promise<string>;
}

export function loadGmailConfig(path: string): Config {
  const config = JSON.parse(readFileSync(path, "utf8")) as Config;
  for (const field of [
    config.account,
    config.clientId,
    config.clientSecret,
    config.refreshToken,
  ]) {
    if (typeof field !== "string" || !field.trim())
      throw new Error("Missing Gmail configuration field");
  }
  if (
    !Array.isArray(config.senders) ||
    config.senders.length === 0 ||
    ![config.account, ...config.senders].every(
      (s) =>
        typeof s === "string" && /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$/.test(s),
    )
  ) {
    throw new Error("Gmail account and senders must be plain email addresses");
  }
  config.account = config.account.toLowerCase();
  config.senders = config.senders.map((sender) => sender.toLowerCase());
  return config;
}

/** Only GET requests are exposed for Gmail; OAuth refresh is a separate endpoint. */
export async function gmailReader(config: Config): Promise<GmailReader> {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      refresh_token: config.refreshToken,
      grant_type: "refresh_token",
    }),
  });
  if (!response.ok)
    throw new Error(
      `OAuth refresh failed (${response.status}); reauthorise if required`,
    );
  const token = (await response.json()) as {
    access_token?: string;
    scope?: string;
  };
  if (!token.access_token || token.scope !== READONLY_SCOPE)
    throw new Error("OAuth token must grant exactly gmail.readonly");
  const get = async <T>(path: string): Promise<T> => {
    const result = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/${path}`,
      {
        redirect: "error",
        headers: { Authorization: `Bearer ${token.access_token}` },
        signal: AbortSignal.timeout(30_000),
      },
    );
    if (!result.ok) throw new Error(`Gmail read failed (${result.status})`);
    // Bound encoded attachments and metadata before JSON parsing.
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (!result.body) throw new Error("Empty Gmail response");
    for await (const chunk of result.body) {
      size += chunk.length;
      if (size > MAX_REPORT_BYTES * 2)
        throw new Error("Gmail response exceeds size limit");
      chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as T;
  };
  const profile = await get<{ emailAddress: string }>("profile");
  if (profile.emailAddress.toLowerCase() !== config.account.toLowerCase())
    throw new Error("OAuth account does not match configuration");
  return {
    account: profile.emailAddress,
    async *list(senders) {
      let page: string | undefined;
      const seen = new Set<string>();
      do {
        const query = new URLSearchParams({
          q: `{${senders.map((s) => `from:${s}`).join(" ")}} has:attachment`,
          maxResults: "100",
        });
        if (page) query.set("pageToken", page);
        const result = await get<{
          messages?: { id: string }[];
          nextPageToken?: string;
        }>(`messages?${query}`);
        for (const message of result.messages ?? []) yield message.id;
        page = result.nextPageToken;
        if (page && seen.has(page))
          throw new Error("Repeated Gmail page token");
        if (page) seen.add(page);
      } while (page);
    },
    message: (id) =>
      get<Message>(`messages/${encodeURIComponent(id)}?format=full`),
    attachment: async (id, attachmentId) =>
      (
        await get<{ data: string }>(
          `messages/${encodeURIComponent(id)}/attachments/${encodeURIComponent(attachmentId)}`,
        )
      ).data,
  };
}

export function attachments(part: Part): Part[] {
  return [
    ...(part.filename || part.body?.attachmentId ? [part] : []),
    ...(part.parts ?? []).flatMap(attachments),
  ];
}
export function reviewLink(account: string, id: string): string {
  // A direct message link avoids a broad sender query and ambiguous RFC Message-ID values.
  if (!/^[a-f0-9]+$/i.test(id)) throw new Error("Invalid Gmail message ID");
  return `https://mail.google.com/mail/u/?authuser=${encodeURIComponent(account)}#all/${id}`;
}

export async function ingestGmail(
  db: Database,
  paths: DataPaths,
  reader: GmailReader,
  senders: string[],
  dryRun = false,
  review = false,
  dryIdentities = new Map<string, string>(),
) {
  const ledgerPath = join(paths.dataDir, "gmail.sqlite");
  // Dry runs use an in-memory ledger, never creating persistent tracking.
  const ledger = new DatabaseSync(dryRun ? ":memory:" : ledgerPath);
  if (!dryRun) chmodSync(ledgerPath, 0o600);
  ledger.exec(`PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS attachments (account TEXT, message TEXT, part TEXT, hashes TEXT NOT NULL, PRIMARY KEY(account,message,part));
    CREATE TABLE IF NOT EXISTS attempts (account TEXT, message TEXT, part TEXT, error TEXT, PRIMARY KEY(account,message,part));
    CREATE TABLE IF NOT EXISTS messages (account TEXT, message TEXT, complete INTEGER NOT NULL, PRIMARY KEY(account,message));`);
  const results: {
    id: string;
    status: string;
    attachments: number;
    error?: string;
    link?: string;
  }[] = [];
  const validHashes = (hashes: string[]) =>
    hashes.length > 0 &&
    hashes.every(
      (sha) =>
        db.get("SELECT 1 FROM reports WHERE source_sha256=:sha", { sha }) !==
        undefined,
    );
  try {
    if (review) {
      for (const row of ledger
        .prepare("SELECT message FROM messages WHERE account=? AND complete=1")
        .all(reader.account)) {
        const id = String(row["message"]);
        const entries = ledger
          .prepare(
            "SELECT hashes FROM attachments WHERE account=? AND message=?",
          )
          .all(reader.account, id);
        if (
          entries.length &&
          entries.every((entry) =>
            validHashes(JSON.parse(String(entry["hashes"])) as string[]),
          )
        ) {
          results.push({
            id,
            status: "complete",
            attachments: entries.length,
            link: reviewLink(reader.account, id),
          });
        }
      }
      return results;
    }
    const seen = new Set<string>();
    for await (const id of reader.list(senders)) {
      if (seen.has(id)) continue;
      seen.add(id);
      let count = 0;
      if (!dryRun)
        ledger
          .prepare("INSERT OR REPLACE INTO messages VALUES (?,?,0)")
          .run(reader.account, id);
      try {
        const message = await reader.message(id);
        if (message.id !== id || !message.payload)
          throw new Error("Incomplete Gmail message");
        const from = message.payload.headers?.filter(
          (h) => h.name.toLowerCase() === "from",
        );
        const value = from?.length === 1 ? (from[0]?.value.trim() ?? "") : "";
        const address = /^(?:[^<>]*<([^<>]+)>|([^<>\s]+))$/.exec(value);
        if (
          !senders.some(
            (sender) =>
              sender.toLowerCase() ===
              (address?.[1] ?? address?.[2] ?? "").toLowerCase(),
          )
        )
          throw new Error("Sender is not in allowlist");
        const parts = attachments(message.payload);
        if (!parts.length) throw new Error("No attachments");
        if (!dryRun)
          ledger
            .prepare("INSERT OR REPLACE INTO messages VALUES (?,?,0)")
            .run(reader.account, id);
        const errors: string[] = [];
        for (const [index, part] of parts.entries()) {
          const key = `${index}:${part.partId ?? ""}`;
          try {
            const previous = ledger
              .prepare(
                "SELECT hashes FROM attachments WHERE account=? AND message=? AND part=?",
              )
              .get(reader.account, id, key);
            if (
              previous &&
              validHashes(JSON.parse(String(previous["hashes"])) as string[])
            ) {
              count++;
              continue;
            }
            if ((part.body?.size ?? 0) > MAX_REPORT_BYTES)
              throw new Error("Attachment exceeds size limit");
            const encoded =
              part.body?.data ??
              (part.body?.attachmentId
                ? await reader.attachment(id, part.body.attachmentId)
                : "");
            if (!encoded || !/^[A-Za-z0-9_=-]+$/.test(encoded))
              throw new Error("Missing or invalid attachment data");
            const sources = reportSourcesFromBuffer(
              Buffer.from(encoded, "base64url"),
              `gmail:${id}:${key}:${part.filename ?? "attachment"}`,
            );
            const hashes: string[] = [];
            for (const source of sources) {
              parseReport(source.data.toString("utf8"));
              const sha = createHash("sha256")
                .update(source.data)
                .digest("hex");
              if (dryRun) {
                const report = parseReport(source.data.toString("utf8"));
                const conflict = db.get(
                  "SELECT source_sha256 FROM reports WHERE reporter=:reporter AND report_id=:id",
                  { reporter: report.reporter, id: report.reportId },
                );
                const identity = JSON.stringify([
                  report.reporter,
                  report.reportId,
                ]);
                const earlier = dryIdentities.get(identity);
                if (
                  (earlier !== undefined && earlier !== sha) ||
                  (conflict && conflict["source_sha256"] !== sha)
                )
                  throw new Error("Report identity conflict");
                dryIdentities.set(identity, sha);
              } else {
                const result = importReport(db, source, {
                  dataDir: paths.dataDir,
                  archiveDir: paths.archive,
                });
                if (result.status === "conflict")
                  throw new Error(result.message);
              }
              hashes.push(sha);
            }
            if (!dryRun)
              ledger
                .prepare("INSERT OR REPLACE INTO attachments VALUES (?,?,?,?)")
                .run(reader.account, id, key, JSON.stringify(hashes));
            if (!dryRun)
              ledger
                .prepare(
                  "DELETE FROM attempts WHERE account=? AND message=? AND part=?",
                )
                .run(reader.account, id, key);
            count++;
          } catch (error) {
            if (!dryRun)
              ledger
                .prepare("INSERT OR REPLACE INTO attempts VALUES (?,?,?,?)")
                .run(
                  reader.account,
                  id,
                  key,
                  error instanceof Error ? error.message : "failed",
                );
            errors.push(
              `Attachment ${index + 1}: ${error instanceof Error ? error.message : "failed"}`,
            );
          }
        }
        if (errors.length) throw new Error(errors.join("; "));
        if (!dryRun)
          ledger
            .prepare(
              "UPDATE messages SET complete=1 WHERE account=? AND message=?",
            )
            .run(reader.account, id);
        results.push({
          id,
          status: dryRun ? "validated" : "complete",
          attachments: count,
          ...(!dryRun ? { link: reviewLink(reader.account, id) } : {}),
        });
      } catch (error) {
        results.push({
          id,
          status: "failed",
          attachments: count,
          error: error instanceof Error ? error.message : "failed",
        });
      }
    }
    return results;
  } finally {
    ledger.close();
  }
}
