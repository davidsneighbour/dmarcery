import type { Database, Params, Row } from "./db.ts";
import { formatNumber } from "./format.ts";
import { cidrRange, ipKey, networkOf } from "./ip.ts";

export interface Filter {
  days?: number;
  domain?: string;
  reporter?: string;
}

const DAY = 86_400;

export function sinceOf(
  days: number | undefined,
  now = Date.now(),
): number | null {
  return days === undefined ? null : Math.floor(now / 1000) - days * DAY;
}

function where(
  filter: Filter,
  columns: { end: string; domain: string; reporter?: string },
): { sql: string; params: Params } {
  const clauses: string[] = [];
  const params: Params = {};
  const since = sinceOf(filter.days);
  if (since !== null) {
    clauses.push(`${columns.end} >= :since`);
    params["since"] = since;
  }
  if (filter.domain !== undefined) {
    clauses.push(`${columns.domain} = :domain`);
    params["domain"] = filter.domain.toLowerCase();
  }
  if (filter.reporter !== undefined && columns.reporter !== undefined) {
    clauses.push(`${columns.reporter} = :reporter COLLATE NOCASE`);
    params["reporter"] = filter.reporter;
  }
  return {
    sql: clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "",
    params,
  };
}

const num = (value: unknown): number => Number(value ?? 0);
const messagesText = (count: number): string =>
  `${formatNumber(count)} message${count === 1 ? "" : "s"}`;
const str = (value: unknown): string | null =>
  value === null || value === undefined ? null : String(value);

export interface Summary {
  reports: number;
  messages: number;
  domains: number;
  reporters: number;
  knownSenders: number;
  firstDate: string | null;
  lastDate: string | null;
  days: number;
  window: {
    reports: number;
    messages: number;
    pass: number;
    fail: number;
    unknownSenders: number;
  };
}

export function summary(db: Database, days = 30): Summary {
  const totals = db.get(`
    SELECT
      (SELECT count(*) FROM reports)                                   AS reports,
      (SELECT coalesce(sum(message_count), 0) FROM records)            AS messages,
      (SELECT count(DISTINCT domain) FROM reports)                     AS domains,
      (SELECT count(DISTINCT reporter) FROM reports)                   AS reporters,
      (SELECT count(*) FROM senders WHERE status = 'known')            AS known_senders,
      (SELECT date(min(period_begin), 'unixepoch') FROM reports)       AS first_date,
      (SELECT date(max(period_end), 'unixepoch') FROM reports)         AS last_date`);
  const since = sinceOf(days) ?? 0;
  const window = db.get(
    `SELECT count(DISTINCT report_pk) AS reports,
            coalesce(sum(message_count), 0) AS messages,
            coalesce(sum(CASE WHEN dmarc_result = 'pass' THEN message_count END), 0) AS pass,
            coalesce(sum(CASE WHEN dmarc_result = 'fail' THEN message_count END), 0) AS fail
     FROM v_records WHERE period_end >= :since`,
    { since },
  );
  const unknown = db.get(
    "SELECT count(*) AS n FROM v_unknown_senders WHERE last_seen_ts >= :since",
    { since },
  );
  return {
    reports: num(totals?.["reports"]),
    messages: num(totals?.["messages"]),
    domains: num(totals?.["domains"]),
    reporters: num(totals?.["reporters"]),
    knownSenders: num(totals?.["known_senders"]),
    firstDate: str(totals?.["first_date"]),
    lastDate: str(totals?.["last_date"]),
    days,
    window: {
      reports: num(window?.["reports"]),
      messages: num(window?.["messages"]),
      pass: num(window?.["pass"]),
      fail: num(window?.["fail"]),
      unknownSenders: num(unknown?.["n"]),
    },
  };
}

export function listReports(
  db: Database,
  filter: Filter,
  limit?: number,
): Row[] {
  const { sql, params } = where(filter, {
    end: "rep.period_end",
    domain: "rep.domain",
    reporter: "rep.reporter",
  });
  return db.all(
    `SELECT date(rep.period_begin, 'unixepoch') AS date, rep.reporter, rep.domain, rep.report_id,
            count(r.id) AS records,
            coalesce(sum(r.message_count), 0) AS messages,
            coalesce(sum(CASE WHEN r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass' THEN r.message_count END), 0) AS pass,
            coalesce(sum(CASE WHEN r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass' THEN 0 ELSE r.message_count END), 0) AS fail,
            rep.policy_p, rep.archive_path
     FROM reports rep LEFT JOIN records r ON r.report_id = rep.id
     ${sql}
     GROUP BY rep.id
     ORDER BY rep.period_begin DESC, rep.reporter
     ${limit === undefined ? "" : `LIMIT ${Math.max(1, Math.floor(limit))}`}`,
    params,
  );
}

export function listFailures(db: Database, filter: Filter): Row[] {
  const { sql, params } = where(filter, {
    end: "period_end",
    domain: "domain",
    reporter: "reporter",
  });
  return db.all(
    `SELECT report_date, domain, reporter, source_ip, message_count, header_from,
            dkim_evaluation, spf_evaluation, dkim_auth, spf_auth, disposition
     FROM v_dmarc_failures ${sql}
     ORDER BY period_begin DESC, message_count DESC`,
    params,
  );
}

export function listUnknown(db: Database, filter: Filter): Row[] {
  const clauses: string[] = [];
  const params: Params = {};
  const since = sinceOf(filter.days);
  if (since !== null) {
    clauses.push("last_seen_ts >= :since");
    params["since"] = since;
  }
  if (filter.domain !== undefined) {
    clauses.push("(',' || domains || ',') LIKE ('%,' || :domain || ',%')");
    params["domain"] = filter.domain.toLowerCase();
  }
  return db.all(
    `SELECT first_seen, last_seen, source_ip, message_count, pass, fail, header_from, domains,
            reporters, dkim_domains, spf_domains, matched_senders
     FROM v_unknown_senders
     ${clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : ""}
     ORDER BY last_seen_ts DESC, message_count DESC`,
    params,
  );
}

export function listDaily(db: Database, filter: Filter): Row[] {
  const clauses: string[] = [];
  const params: Params = {};
  const since = sinceOf(filter.days);
  if (since !== null) {
    clauses.push("date >= date(:since, 'unixepoch')");
    params["since"] = since;
  }
  if (filter.domain !== undefined) {
    clauses.push("domain = :domain");
    params["domain"] = filter.domain.toLowerCase();
  }
  return db.all(
    `SELECT date, domain, reports, messages, pass, fail, quarantine, reject FROM v_daily_summary
     ${clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : ""}
     ORDER BY date DESC, domain`,
    params,
  );
}

export function listDomains(db: Database): Row[] {
  return db.all(
    `SELECT domain, group_concat(source, ', ') AS seen_as, min(first_seen) AS first_seen,
            max(last_seen) AS last_seen, max(message_count) AS message_count
     FROM (SELECT * FROM v_domains ORDER BY source)
     GROUP BY domain
     ORDER BY domain`,
  );
}

export interface Counted {
  value: string;
  messages: number;
}

export interface SenderInspection {
  query: string;
  kind: "ip" | "cidr" | "domain";
  records: number;
  messages: number;
  pass: number;
  fail: number;
  firstSeen: string | null;
  lastSeen: string | null;
  sourceIps: Counted[];
  headerFrom: Counted[];
  dkim: Counted[];
  spf: Counted[];
  reporters: Counted[];
  policyDomains: Counted[];
  dispositions: Counted[];
  registry: Counted[];
}

/** Aggregates every observation that involves an IP address, CIDR range, or domain. */
export function inspectSender(db: Database, query: string): SenderInspection {
  const value = query.trim().toLowerCase();
  let kind: SenderInspection["kind"];
  let condition: string;
  const params: Params = {};

  const key = ipKey(value);
  const range = value.includes("/") ? cidrRange(value) : null;
  if (key !== null) {
    kind = "ip";
    condition = "v.source_ip_key = :key";
    params["key"] = key;
  } else if (range !== null) {
    kind = "cidr";
    condition = "v.source_ip_key BETWEEN :start AND :end";
    params["start"] = range.start;
    params["end"] = range.end;
  } else {
    kind = "domain";
    condition = `(v.header_from = :domain OR v.envelope_from = :domain
      OR EXISTS (SELECT 1 FROM dkim_results d WHERE d.record_id = v.record_id AND d.domain = :domain)
      OR EXISTS (SELECT 1 FROM spf_results s WHERE s.record_id = v.record_id AND s.domain = :domain))`;
    params["domain"] = value.replace(/\.$/, "");
  }

  const matched = `matched AS (SELECT * FROM v_records v WHERE ${condition})`;
  const counted = (select: string, from = "matched"): Counted[] =>
    db
      .all(
        `WITH ${matched} SELECT ${select} AS value, sum(messages) AS messages FROM (${from}) GROUP BY 1 ORDER BY 2 DESC, 1`,
        params,
      )
      .map((row) => ({
        value: String(row["value"] ?? "?"),
        messages: num(row["messages"]),
      }));

  const totals = db.get(
    `WITH ${matched}
     SELECT count(*) AS records,
            coalesce(sum(message_count), 0) AS messages,
            coalesce(sum(CASE WHEN dmarc_result = 'pass' THEN message_count END), 0) AS pass,
            coalesce(sum(CASE WHEN dmarc_result = 'fail' THEN message_count END), 0) AS fail,
            date(min(period_begin), 'unixepoch') AS first_seen,
            date(max(period_end), 'unixepoch') AS last_seen
     FROM matched`,
    params,
  );

  return {
    query,
    kind,
    records: num(totals?.["records"]),
    messages: num(totals?.["messages"]),
    pass: num(totals?.["pass"]),
    fail: num(totals?.["fail"]),
    firstSeen: str(totals?.["first_seen"]),
    lastSeen: str(totals?.["last_seen"]),
    sourceIps: counted(
      "source_ip",
      "SELECT source_ip, message_count AS messages FROM matched",
    ),
    headerFrom: counted(
      "header_from",
      "SELECT header_from, message_count AS messages FROM matched",
    ),
    dkim: counted(
      "entry",
      `SELECT coalesce(d.domain, '?') || coalesce(' (selector ' || d.selector || ')', '') || ': ' || coalesce(d.result, '?') AS entry,
              m.message_count AS messages
       FROM matched m JOIN dkim_results d ON d.record_id = m.record_id`,
    ),
    spf: counted(
      "entry",
      `SELECT coalesce(s.domain, '?') || coalesce(' (' || s.scope || ')', '') || ': ' || coalesce(s.result, '?') AS entry,
              m.message_count AS messages
       FROM matched m JOIN spf_results s ON s.record_id = m.record_id`,
    ),
    reporters: counted(
      "reporter",
      "SELECT reporter, message_count AS messages FROM matched",
    ),
    policyDomains: counted(
      "domain",
      "SELECT domain, message_count AS messages FROM matched",
    ),
    dispositions: counted(
      "disposition",
      "SELECT disposition, message_count AS messages FROM matched",
    ),
    registry: counted(
      "sender",
      `SELECT s.name || ' (' || s.status || ', matched by ' || (
                SELECT group_concat(DISTINCT rm.identifier_type)
                FROM matched m JOIN v_record_sender_matches rm ON rm.record_id = m.record_id
                WHERE rm.sender_id = s.id) || ')' AS sender,
              sum(x.message_count) AS messages
       FROM (SELECT DISTINCT m.record_id, rm.sender_id, m.message_count
             FROM matched m JOIN v_record_sender_matches rm ON rm.record_id = m.record_id) x
       JOIN senders s ON s.id = x.sender_id
       GROUP BY s.id`,
    ),
  };
}

export interface Anomaly {
  signal: string;
  subject: string;
  firstSeen?: string;
  detail: string;
}

/**
 * Deterministic signals for the last `days` days, compared with the period of
 * the same length before it. No scoring: every signal is a plain observation.
 */
export function anomalies(db: Database, days = 7, now = Date.now()): Anomaly[] {
  const since = sinceOf(days, now) ?? 0;
  const before = since - days * DAY;
  const results: Anomaly[] = [];

  const firstSeen = (signal: string, sql: string): void => {
    for (const row of db.all(sql, { since })) {
      results.push({
        signal,
        subject: String(row["value"]),
        firstSeen: String(row["first_seen"]),
        detail: `${messagesText(num(row["messages"]))} since first seen`,
      });
    }
  };
  const newSql = (value: string, from: string, extra = ""): string => `
    SELECT ${value} AS value, date(min(rep.period_begin), 'unixepoch') AS first_seen, sum(r.message_count) AS messages
    FROM ${from} JOIN reports rep ON rep.id = r.report_id
    ${extra}
    GROUP BY 1 HAVING min(rep.period_begin) >= :since
    ORDER BY 2, 1`;

  firstSeen("new source IP", newSql("r.source_ip", "records r"));
  firstSeen(
    "new header-from",
    newSql("r.header_from", "records r", "WHERE r.header_from IS NOT NULL"),
  );
  firstSeen(
    "new DKIM domain",
    newSql(
      "d.domain",
      "dkim_results d JOIN records r ON r.id = d.record_id",
      "WHERE d.domain IS NOT NULL",
    ),
  );
  firstSeen(
    "new DKIM selector",
    newSql(
      "d.selector || '._domainkey.' || d.domain",
      "dkim_results d JOIN records r ON r.id = d.record_id",
      "WHERE d.domain IS NOT NULL AND d.selector IS NOT NULL",
    ),
  );
  firstSeen(
    "new SPF domain",
    newSql(
      "s.domain",
      "spf_results s JOIN records r ON r.id = s.record_id",
      "WHERE s.domain IS NOT NULL",
    ),
  );

  // New source networks (/24 IPv4, /48 IPv6), computed from per-IP first sightings.
  const networks = new Map<string, { first: number; messages: number }>();
  for (const row of db.all(
    `SELECT r.source_ip, min(rep.period_begin) AS first, sum(r.message_count) AS messages
     FROM records r JOIN reports rep ON rep.id = r.report_id GROUP BY r.source_ip`,
  )) {
    const network = networkOf(String(row["source_ip"]));
    if (network === null) {
      continue;
    }
    const current = networks.get(network);
    const first = num(row["first"]);
    networks.set(network, {
      first: current === undefined ? first : Math.min(current.first, first),
      messages: (current?.messages ?? 0) + num(row["messages"]),
    });
  }
  for (const [network, { first, messages }] of [...networks].sort(
    (a, b) => a[1].first - b[1].first,
  )) {
    if (first >= since) {
      results.push({
        signal: "new source network",
        subject: network,
        firstSeen: new Date(first * 1000).toISOString().slice(0, 10),
        detail: `${messagesText(messages)} since first seen`,
      });
    }
  }

  // Volume and failure trends per domain: this period against the previous period of equal length.
  const periods = db.all(
    `SELECT rep.domain,
            coalesce(sum(CASE WHEN rep.period_begin >= :since THEN r.message_count END), 0) AS current_messages,
            coalesce(sum(CASE WHEN rep.period_begin >= :since AND NOT (r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass')
                              THEN r.message_count END), 0) AS current_fail,
            coalesce(sum(CASE WHEN rep.period_begin < :since THEN r.message_count END), 0) AS previous_messages,
            coalesce(sum(CASE WHEN rep.period_begin < :since AND NOT (r.dkim_evaluation = 'pass' OR r.spf_evaluation = 'pass')
                              THEN r.message_count END), 0) AS previous_fail
     FROM reports rep JOIN records r ON r.report_id = rep.id
     WHERE rep.period_begin >= :before
     GROUP BY rep.domain ORDER BY rep.domain`,
    { since, before },
  );
  const percent = (part: number, whole: number): string =>
    whole === 0 ? "0%" : `${((100 * part) / whole).toFixed(1)}%`;
  for (const row of periods) {
    const domain = String(row["domain"]);
    const current = num(row["current_messages"]);
    const previous = num(row["previous_messages"]);
    const currentFail = num(row["current_fail"]);
    const previousFail = num(row["previous_fail"]);
    const comparison = `last ${days} days: ${current}, previous ${days} days: ${previous}`;

    if (
      previous > 0 &&
      (current >= Math.max(3 * previous, previous + 10) ||
        (previous >= 10 && current <= previous / 3))
    ) {
      results.push({
        signal: "volume change",
        subject: domain,
        detail: `messages ${comparison}`,
      });
    }
    const currentRate = current === 0 ? 0 : currentFail / current;
    const previousRate = previous === 0 ? 0 : previousFail / previous;
    if (
      currentFail > 0 &&
      currentFail > previousFail &&
      currentRate > previousRate
    ) {
      results.push({
        signal: "failures increasing",
        subject: domain,
        detail: `DMARC fail last ${days} days: ${currentFail} (${percent(currentFail, current)}), previous ${days} days: ${previousFail} (${percent(previousFail, previous)})`,
      });
    }
  }

  const unknown = db.get(
    "SELECT count(*) AS n, coalesce(sum(message_count), 0) AS messages FROM v_unknown_senders WHERE last_seen_ts >= :since",
    {
      since,
    },
  );
  const registered = num(db.get("SELECT count(*) AS n FROM senders")?.["n"]);
  if (registered > 0 && num(unknown?.["n"]) > 0) {
    results.push({
      signal: "unknown senders",
      subject: `${num(unknown?.["n"])} sender(s)`,
      detail:
        "observations not matched by a known or ignored sender; run: dmarc unknown",
    });
  }

  return results;
}
