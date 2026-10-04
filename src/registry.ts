import type { Database, Row } from "./db.ts";
import { cidrRange, ipKey } from "./ip.ts";

export const SENDER_STATUSES = ["known", "unknown", "ignored", "retired", "investigate"] as const;
export type SenderStatus = (typeof SENDER_STATUSES)[number];

export const IDENTIFIER_TYPES = [
  "source_ip",
  "source_cidr",
  "dkim_domain",
  "dkim_selector",
  "spf_domain",
  "header_from",
] as const;
export type IdentifierType = (typeof IDENTIFIER_TYPES)[number];

export interface Identifier {
  type: IdentifierType;
  value: string;
}

export class RegistryError extends Error {
  override name = "RegistryError";
}

export function isSenderStatus(value: string): value is SenderStatus {
  return (SENDER_STATUSES as readonly string[]).includes(value);
}

interface NormalisedIdentifier extends Identifier {
  rangeStart: string | null;
  rangeEnd: string | null;
}

function normalise(identifier: Identifier): NormalisedIdentifier {
  const value = identifier.value.trim().toLowerCase().replace(/\.$/, "");
  switch (identifier.type) {
    case "source_ip": {
      const key = ipKey(value);
      if (key === null) {
        throw new RegistryError(`Not an IP address: ${identifier.value}`);
      }
      return { type: identifier.type, value, rangeStart: key, rangeEnd: key };
    }
    case "source_cidr": {
      const range = cidrRange(value);
      if (range === null || !value.includes("/")) {
        throw new RegistryError(`Not a CIDR range: ${identifier.value}`);
      }
      return { type: identifier.type, value, rangeStart: range.start, rangeEnd: range.end };
    }
    default:
      if (value === "" || /\s/.test(value)) {
        throw new RegistryError(`Invalid ${identifier.type}: ${identifier.value}`);
      }
      return { type: identifier.type, value, rangeStart: null, rangeEnd: null };
  }
}

function findSender(db: Database, name: string): Row | undefined {
  return db.get("SELECT * FROM senders WHERE name = :name", { name });
}

export interface AddSenderOptions {
  status?: SenderStatus;
  notes?: string;
  identifiers: Identifier[];
}

export interface AddSenderResult {
  created: boolean;
  added: number;
}

/** Creates a sender, or updates an existing one and adds identifiers to it. */
export function addSender(db: Database, name: string, options: AddSenderOptions): AddSenderResult {
  const trimmed = name.trim();
  if (trimmed === "") {
    throw new RegistryError("A sender needs a name");
  }
  const identifiers = options.identifiers.map(normalise);
  const now = new Date().toISOString();

  return db.transaction(() => {
    const existing = findSender(db, trimmed);
    let senderId: number;
    if (existing === undefined) {
      senderId = db.run(
        `INSERT INTO senders (name, status, notes, created_at, updated_at)
         VALUES (:name, :status, :notes, :now, :now)`,
        { name: trimmed, status: options.status ?? "known", notes: options.notes ?? null, now },
      );
    } else {
      senderId = Number(existing["id"]);
      db.run(
        `UPDATE senders SET
           status = coalesce(:status, status),
           notes = coalesce(:notes, notes),
           updated_at = :now
         WHERE id = :id`,
        { id: senderId, status: options.status ?? null, notes: options.notes ?? null, now },
      );
    }
    let added = 0;
    for (const identifier of identifiers) {
      const before = db.get(
        "SELECT 1 FROM sender_identifiers WHERE sender_id = :id AND identifier_type = :type AND identifier_value = :value",
        { id: senderId, type: identifier.type, value: identifier.value },
      );
      if (before !== undefined) {
        continue;
      }
      db.run(
        `INSERT INTO sender_identifiers (sender_id, identifier_type, identifier_value, range_start, range_end, created_at)
         VALUES (:id, :type, :value, :start, :end, :now)`,
        {
          id: senderId,
          type: identifier.type,
          value: identifier.value,
          start: identifier.rangeStart,
          end: identifier.rangeEnd,
          now,
        },
      );
      added += 1;
    }
    return { created: existing === undefined, added };
  });
}

/**
 * Removes identifiers from a sender, or the whole sender when no identifiers
 * are given. Returns the number of removed rows.
 */
export function removeSender(db: Database, name: string, identifiers: Identifier[]): number {
  const sender = findSender(db, name.trim());
  if (sender === undefined) {
    throw new RegistryError(`No sender named "${name}"`);
  }
  const id = Number(sender["id"]);
  return db.transaction(() => {
    if (identifiers.length === 0) {
      db.run("DELETE FROM senders WHERE id = :id", { id });
      return 1;
    }
    let removed = 0;
    for (const identifier of identifiers.map(normalise)) {
      const before = db.get(
        "SELECT id FROM sender_identifiers WHERE sender_id = :id AND identifier_type = :type AND identifier_value = :value",
        { id, type: identifier.type, value: identifier.value },
      );
      if (before !== undefined) {
        db.run("DELETE FROM sender_identifiers WHERE id = :id", { id: Number(before["id"]) });
        removed += 1;
      }
    }
    db.run("UPDATE senders SET updated_at = :now WHERE id = :id", { id, now: new Date().toISOString() });
    return removed;
  });
}

export interface SenderIdentifierView {
  type: string;
  value: string;
  firstSeen: string | null;
  lastSeen: string | null;
  messages: number;
}

export interface SenderView {
  name: string;
  status: string;
  notes: string | null;
  identifiers: SenderIdentifierView[];
}

/** Lists the registry. first_seen and last_seen are derived from observations, never stored. */
export function listSenders(db: Database): SenderView[] {
  const senders = db.all("SELECT id, name, status, notes FROM senders ORDER BY name COLLATE NOCASE");
  return senders.map((sender) => ({
    name: String(sender["name"]),
    status: String(sender["status"]),
    notes: sender["notes"] === null ? null : String(sender["notes"]),
    identifiers: db
      .all(
        `SELECT si.identifier_type, si.identifier_value,
                date(min(v.period_begin), 'unixepoch') AS first_seen,
                date(max(v.period_end), 'unixepoch')   AS last_seen,
                coalesce(sum(v.message_count), 0)      AS messages
         FROM sender_identifiers si
         LEFT JOIN v_record_sender_matches m
           ON m.sender_id = si.sender_id AND m.identifier_type = si.identifier_type AND m.identifier_value = si.identifier_value
         LEFT JOIN v_records v ON v.record_id = m.record_id
         WHERE si.sender_id = :id
         GROUP BY si.id
         ORDER BY si.identifier_type, si.identifier_value`,
        { id: Number(sender["id"]) },
      )
      .map((row) => ({
        type: String(row["identifier_type"]),
        value: String(row["identifier_value"]),
        firstSeen: row["first_seen"] === null ? null : String(row["first_seen"]),
        lastSeen: row["last_seen"] === null ? null : String(row["last_seen"]),
        messages: Number(row["messages"]),
      })),
  }));
}
