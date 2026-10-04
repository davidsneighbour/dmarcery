import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

export type Row = Record<string, string | number | bigint | null | Uint8Array>;
export type Params = Record<string, SQLInputValue>;

interface Migration {
  version: number;
  name: string;
  sql: string;
}

/*
 * Migrations are append-only. Never edit a migration that has been released;
 * add a new one instead. Views may be dropped and recreated in later migrations.
 */
const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: "initial schema",
    sql: `
      -- Observed data: what DMARC reports said.

      CREATE TABLE reports (
        id                 INTEGER PRIMARY KEY,
        reporter           TEXT    NOT NULL,
        report_id          TEXT    NOT NULL,
        report_email       TEXT,
        extra_contact_info TEXT,
        report_version     TEXT,
        report_errors      TEXT,   -- JSON array of <error> elements, NULL if none
        domain             TEXT    NOT NULL,
        period_begin       INTEGER NOT NULL, -- Unix seconds, UTC
        period_end         INTEGER NOT NULL, -- Unix seconds, UTC
        policy_adkim       TEXT,
        policy_aspf        TEXT,
        policy_p           TEXT,
        policy_sp          TEXT,
        policy_pct         INTEGER,
        policy_np          TEXT,
        policy_fo          TEXT,
        source_file        TEXT    NOT NULL, -- file name at import time
        archive_path       TEXT    NOT NULL, -- relative to the data directory
        source_sha256      TEXT    NOT NULL UNIQUE,
        imported_at        TEXT    NOT NULL,
        UNIQUE (reporter, report_id)
      );
      CREATE INDEX reports_domain_period ON reports (domain, period_begin);
      CREATE INDEX reports_period ON reports (period_begin);

      CREATE TABLE records (
        id              INTEGER PRIMARY KEY,
        report_id       INTEGER NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
        source_ip       TEXT    NOT NULL,
        source_ip_key   TEXT,   -- 32 hex characters, IPv4 mapped into IPv6; used for CIDR matching
        message_count   INTEGER NOT NULL,
        header_from     TEXT,
        envelope_from   TEXT,
        envelope_to     TEXT,
        disposition     TEXT,
        dkim_evaluation TEXT,   -- policy_evaluated/dkim, as reported by the receiver
        spf_evaluation  TEXT    -- policy_evaluated/spf, as reported by the receiver
      );
      CREATE INDEX records_report ON records (report_id);
      CREATE INDEX records_source_ip_key ON records (source_ip_key);
      CREATE INDEX records_header_from ON records (header_from);

      -- policy_evaluated/reason may occur more than once per record.
      CREATE TABLE policy_reasons (
        id        INTEGER PRIMARY KEY,
        record_id INTEGER NOT NULL REFERENCES records (id) ON DELETE CASCADE,
        type      TEXT,
        comment   TEXT
      );
      CREATE INDEX policy_reasons_record ON policy_reasons (record_id);

      CREATE TABLE dkim_results (
        id           INTEGER PRIMARY KEY,
        record_id    INTEGER NOT NULL REFERENCES records (id) ON DELETE CASCADE,
        domain       TEXT,
        selector     TEXT,
        result       TEXT,
        human_result TEXT
      );
      CREATE INDEX dkim_results_record ON dkim_results (record_id);
      CREATE INDEX dkim_results_domain ON dkim_results (domain);

      CREATE TABLE spf_results (
        id           INTEGER PRIMARY KEY,
        record_id    INTEGER NOT NULL REFERENCES records (id) ON DELETE CASCADE,
        domain       TEXT,
        scope        TEXT,
        result       TEXT,
        human_result TEXT
      );
      CREATE INDEX spf_results_record ON spf_results (record_id);
      CREATE INDEX spf_results_domain ON spf_results (domain);

      -- Configured data: what we declare. Never written by the importer.

      CREATE TABLE senders (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
        status     TEXT NOT NULL DEFAULT 'known'
                   CHECK (status IN ('known', 'unknown', 'ignored', 'retired', 'investigate')),
        notes      TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE sender_identifiers (
        id               INTEGER PRIMARY KEY,
        sender_id        INTEGER NOT NULL REFERENCES senders (id) ON DELETE CASCADE,
        identifier_type  TEXT    NOT NULL
                         CHECK (identifier_type IN ('source_ip', 'source_cidr', 'dkim_domain', 'dkim_selector', 'spf_domain', 'header_from')),
        identifier_value TEXT    NOT NULL,
        range_start      TEXT,   -- IP key range for source_ip and source_cidr
        range_end        TEXT,
        created_at       TEXT    NOT NULL,
        UNIQUE (sender_id, identifier_type, identifier_value)
      );
      CREATE INDEX sender_identifiers_value ON sender_identifiers (identifier_type, identifier_value);

      -- Views. Dates are UTC.

      CREATE VIEW v_records AS
      SELECT
        r.id                                     AS record_id,
        rep.id                                   AS report_pk,
        rep.reporter,
        rep.report_id,
        rep.domain,
        rep.period_begin,
        rep.period_end,
        date(rep.period_begin, 'unixepoch')      AS report_date,
        r.source_ip,
        r.source_ip_key,
        r.message_count,
        r.header_from,
        r.envelope_from,
        r.envelope_to,
        r.disposition,
        r.dkim_evaluation,
        r.spf_evaluation,
        CASE WHEN r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass'
             THEN 'pass' ELSE 'fail' END         AS dmarc_result,
        (SELECT group_concat(domain, ', ') FROM (
           SELECT DISTINCT domain FROM dkim_results
           WHERE record_id = r.id AND domain IS NOT NULL ORDER BY domain))      AS dkim_domains,
        (SELECT group_concat(entry, ', ') FROM (
           SELECT coalesce(domain, '?') || coalesce('/' || selector, '') || '=' || coalesce(result, '?') AS entry
           FROM dkim_results WHERE record_id = r.id ORDER BY id))               AS dkim_auth,
        (SELECT group_concat(domain, ', ') FROM (
           SELECT DISTINCT domain FROM spf_results
           WHERE record_id = r.id AND domain IS NOT NULL ORDER BY domain))      AS spf_domains,
        (SELECT group_concat(entry, ', ') FROM (
           SELECT coalesce(domain, '?') || '=' || coalesce(result, '?') AS entry
           FROM spf_results WHERE record_id = r.id ORDER BY id))                AS spf_auth
      FROM records r
      JOIN reports rep ON rep.id = r.report_id;

      CREATE VIEW v_dmarc_failures AS
      SELECT report_date, period_begin, period_end, domain, reporter, report_id, source_ip, message_count,
             header_from, dkim_evaluation, spf_evaluation, dkim_auth, spf_auth, disposition, record_id
      FROM v_records
      WHERE dmarc_result = 'fail';

      CREATE VIEW v_senders AS
      SELECT
        source_ip,
        header_from,
        dkim_domains                               AS dkim_domain,
        spf_domains                                AS spf_domain,
        date(min(period_begin), 'unixepoch')       AS first_seen,
        date(max(period_end), 'unixepoch')         AS last_seen,
        sum(message_count)                         AS message_count,
        sum(CASE WHEN dmarc_result = 'pass' THEN message_count ELSE 0 END) AS pass,
        sum(CASE WHEN dmarc_result = 'fail' THEN message_count ELSE 0 END) AS fail
      FROM v_records
      GROUP BY source_ip, header_from, dkim_domains, spf_domains;

      -- Which registry senders a record matches. Rules:
      --   source_ip, source_cidr: source IP inside the identifier range
      --   dkim_domain, dkim_selector: a DKIM result with that value and result=pass
      --   spf_domain: an SPF result with that domain and result=pass
      --   header_from: header_from equal and the receiver evaluated DMARC as pass
      CREATE VIEW v_record_sender_matches AS
      SELECT r.id AS record_id, si.sender_id, si.identifier_type, si.identifier_value
      FROM records r
      JOIN sender_identifiers si
        ON si.identifier_type IN ('source_ip', 'source_cidr')
       AND r.source_ip_key BETWEEN si.range_start AND si.range_end
      UNION
      SELECT d.record_id, si.sender_id, si.identifier_type, si.identifier_value
      FROM dkim_results d
      JOIN sender_identifiers si
        ON si.identifier_type = 'dkim_domain' AND si.identifier_value = d.domain
      WHERE d.result = 'pass'
      UNION
      SELECT d.record_id, si.sender_id, si.identifier_type, si.identifier_value
      FROM dkim_results d
      JOIN sender_identifiers si
        ON si.identifier_type = 'dkim_selector' AND si.identifier_value = d.selector
      WHERE d.result = 'pass'
      UNION
      SELECT s.record_id, si.sender_id, si.identifier_type, si.identifier_value
      FROM spf_results s
      JOIN sender_identifiers si
        ON si.identifier_type = 'spf_domain' AND si.identifier_value = s.domain
      WHERE s.result = 'pass'
      UNION
      SELECT r.id, si.sender_id, si.identifier_type, si.identifier_value
      FROM records r
      JOIN sender_identifiers si
        ON si.identifier_type = 'header_from' AND si.identifier_value = r.header_from
      WHERE r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass';

      -- Observations not covered by a sender with status 'known' or 'ignored'.
      CREATE VIEW v_unknown_senders AS
      SELECT
        v.source_ip,
        v.header_from,
        date(min(v.period_begin), 'unixepoch')   AS first_seen,
        date(max(v.period_end), 'unixepoch')     AS last_seen,
        min(v.period_begin)                      AS first_seen_ts,
        max(v.period_end)                        AS last_seen_ts,
        sum(v.message_count)                     AS message_count,
        sum(CASE WHEN v.dmarc_result = 'pass' THEN v.message_count ELSE 0 END) AS pass,
        sum(CASE WHEN v.dmarc_result = 'fail' THEN v.message_count ELSE 0 END) AS fail,
        count(*)                                 AS records,
        group_concat(DISTINCT v.domain)          AS domains,
        group_concat(DISTINCT v.reporter)        AS reporters,
        group_concat(DISTINCT v.dkim_domains)    AS dkim_domains,
        group_concat(DISTINCT v.spf_domains)     AS spf_domains,
        (SELECT group_concat(DISTINCT s.name || ' (' || s.status || ')')
           FROM v_records v2
           JOIN v_record_sender_matches m ON m.record_id = v2.record_id
           JOIN senders s ON s.id = m.sender_id
          WHERE v2.source_ip = v.source_ip AND v2.header_from IS v.header_from) AS matched_senders
      FROM v_records v
      WHERE NOT EXISTS (
        SELECT 1 FROM v_record_sender_matches m
        JOIN senders s ON s.id = m.sender_id
        WHERE m.record_id = v.record_id AND s.status IN ('known', 'ignored')
      )
      GROUP BY v.source_ip, v.header_from;

      CREATE VIEW v_daily_summary AS
      SELECT
        date(rep.period_begin, 'unixepoch')      AS date,
        rep.domain,
        count(DISTINCT rep.id)                   AS reports,
        sum(r.message_count)                     AS messages,
        sum(CASE WHEN r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass' THEN r.message_count ELSE 0 END) AS pass,
        sum(CASE WHEN r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass' THEN 0 ELSE r.message_count END) AS fail,
        sum(CASE WHEN r.disposition = 'quarantine' THEN r.message_count ELSE 0 END) AS quarantine,
        sum(CASE WHEN r.disposition = 'reject' THEN r.message_count ELSE 0 END)     AS reject
      FROM reports rep
      JOIN records r ON r.report_id = rep.id
      GROUP BY date, rep.domain;

      CREATE VIEW v_domains AS
      WITH observations (domain, source, report_id, message_count) AS (
        SELECT domain, 'policy', id, 0 FROM reports
        UNION ALL
        SELECT header_from, 'header_from', report_id, message_count FROM records WHERE header_from IS NOT NULL
        UNION ALL
        SELECT envelope_from, 'envelope_from', report_id, message_count FROM records WHERE envelope_from IS NOT NULL
        UNION ALL
        SELECT d.domain, 'dkim', r.report_id, r.message_count
        FROM dkim_results d JOIN records r ON r.id = d.record_id WHERE d.domain IS NOT NULL
        UNION ALL
        SELECT s.domain, 'spf', r.report_id, r.message_count
        FROM spf_results s JOIN records r ON r.id = s.record_id WHERE s.domain IS NOT NULL
      )
      SELECT
        o.domain,
        o.source,
        date(min(rep.period_begin), 'unixepoch') AS first_seen,
        date(max(rep.period_end), 'unixepoch')   AS last_seen,
        sum(o.message_count)                     AS message_count
      FROM observations o
      JOIN reports rep ON rep.id = o.report_id
      GROUP BY o.domain, o.source;
    `,
  },
];

export const SCHEMA_VERSION = Math.max(
  ...MIGRATIONS.map((migration) => migration.version),
);

export class Database {
  readonly db: DatabaseSync;
  readonly path: string;

  constructor(path: string) {
    if (path !== ":memory:") {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.path = path;
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version    INTEGER PRIMARY KEY,
        name       TEXT NOT NULL,
        applied_at TEXT NOT NULL
      )
    `);
    const applied = new Set(
      this.all("SELECT version FROM schema_migrations").map((row) =>
        Number(row["version"]),
      ),
    );
    for (const migration of MIGRATIONS) {
      if (applied.has(migration.version)) {
        continue;
      }
      this.transaction(() => {
        this.db.exec(migration.sql);
        this.run(
          "INSERT INTO schema_migrations (version, name, applied_at) VALUES (:version, :name, :applied_at)",
          {
            version: migration.version,
            name: migration.name,
            applied_at: new Date().toISOString(),
          },
        );
      });
    }
  }

  all(sql: string, params: Params = {}): Row[] {
    return this.db.prepare(sql).all(params) as Row[];
  }

  get(sql: string, params: Params = {}): Row | undefined {
    return this.db.prepare(sql).get(params) as Row | undefined;
  }

  /** Runs a statement and returns the last inserted row id. */
  run(sql: string, params: Params = {}): number {
    return Number(this.db.prepare(sql).run(params).lastInsertRowid);
  }

  transaction<T>(work: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = work();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  close(): void {
    this.db.close();
  }
}
