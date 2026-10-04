# Dmarcery

A local, portable history of DMARC aggregate reports, with a small CLI (`dmarc`) for auditing and anomaly detection. See [Design](#design) for the rules behind it, and the [issues](https://github.com/davidsneighbour/dmarcery/issues) for planned work.

## Requirements

* Node.js 24 or later (uses the built-in `node:sqlite` module and TypeScript type stripping)

## Installation

```bash
npm install
npm run build
npm link        # makes the `dmarc` command available
```

Without linking, run `node dist/cli.js …` or, from source, `npm run dmarc -- …`.

## Usage

```bash
dmarc report.xml                 # import (same as: dmarc import report.xml)
dmarc import report.zip          # zip attachments (for example from Google)
dmarc import report.xml.gz       # gzip attachments (for example from Microsoft)
dmarc import reports/*.xml       # several files
dmarc import -r ~/dmarc-mail/    # a directory, including subdirectories
dmarc import -v report.xml       # full summary per report

dmarc summary                    # totals and the last 30 days
dmarc reports --days 30 --domain example.com --reporter receiver.example
dmarc failures --days 30
dmarc unknown                    # observations not covered by the sender registry
dmarc sender 192.0.2.52          # everything about an IP address
dmarc sender 192.0.2.0/24        # … a range
dmarc sender mail.example.com    # … or a domain (header-from, envelope-from, DKIM, or SPF)
dmarc daily --days 14
dmarc anomalies --days 7
dmarc domains                    # every domain seen in reports
dmarc rebuild                    # recreate the database from the XML archive
```

All query commands accept `--json`. `--data-dir DIR` (or `DMARC_HOME`) selects another data directory.

Exit codes: `0` success (also when a report was already imported), `1` some files were not imported or an inspected sender has no observations, `2` usage error.

## Sender registry

The registry is configured data. The importer never writes to it, and it never changes observations.

```bash
dmarc sender add Resend --status known \
  --dkim-domain mail.example.com \
  --dkim-selector resend \
  --spf-domain bounce.mail.example.com
dmarc sender add Resend --cidr 192.0.2.0/24   # add identifiers to an existing sender
dmarc sender list
dmarc sender remove Resend --cidr 192.0.2.0/24
dmarc sender remove Resend       # remove the sender
```

Statuses: `known`, `unknown`, `ignored`, `retired`, `investigate`. Only `known` and `ignored` remove an observation from `dmarc unknown`. Matches with other statuses stay visible in the `REGISTRY` column.

A record matches a sender when one of these rules applies:

| Identifier | Option | Rule |
| --------------- | ----------------- | ----------------------------------------------------------- |
| `source_ip` | `--ip` | Source IP is equal (IPv6 notation is normalised) |
| `source_cidr` | `--cidr` | Source IP is in the range |
| `dkim_domain` | `--dkim-domain` | A DKIM result with this domain **and** `result = pass` |
| `dkim_selector` | `--dkim-selector` | A DKIM result with this selector **and** `result = pass` |
| `spf_domain` | `--spf-domain` | An SPF result with this domain **and** `result = pass` |
| `header_from` | `--header-from` | Header-from is equal **and** the receiver evaluated DMARC as pass |

A forged message can carry any DKIM domain, SPF domain, or header-from, so these identifiers only match when they passed. A selector on its own is weak: any domain can publish a key with the selector `resend`. Prefer `dkim_domain` and `spf_domain`.

## Data layout

```text
~/.local/share/dmarc/              ($DMARC_HOME, else $XDG_DATA_HOME/dmarc)
├── dmarc.sqlite
└── reports/<domain>/<yyyy>/<mm>/<reporter>-<report-id>.xml
```

Archived reports are byte-for-byte copies of the report XML and are made read-only. For `.zip` and `.gz` files, the archive keeps the extracted XML, not the compressed file. `reports.source_file` records where the report came from, for example `report.zip:report.xml`. `dmarc rebuild` creates a new database from the archive, copies the sender registry over, and keeps the previous database as `dmarc.sqlite.bak`.

### Tables and views

* Observed: `reports`, `records`, `dkim_results`, `spf_results`, `policy_reasons`
* Configured: `senders`, `sender_identifiers`
* Migrations: `schema_migrations` (applied automatically by the CLI)
* Views: `v_records`, `v_dmarc_failures`, `v_senders`, `v_unknown_senders`, `v_daily_summary`, `v_domains`, `v_record_sender_matches`

The views use only standard SQLite, so they also work in the `sqlite3` shell. Dates are UTC. `dmarc_result` is `pass` when the receiver reported `policy_evaluated` DKIM or SPF as `pass`. It is never recalculated.

## Import findings

After each import, the importer compares the report with all earlier reports and prints:

* new source IPs and source networks (/24 for IPv4, /48 for IPv6)
* new header-from domains, DKIM domains, DKIM selectors, and SPF domains
* records not matched by a `known` or `ignored` sender (only when the registry is not empty)
* DMARC failures
* volume changes: at least 3 times the median of the previous 30 reports (and at least 10 more messages) from the same reporter for the same domain, or at most a third of that median when the median is 10 or more

A report without findings prints two lines.

## Compressed reports

The format is detected from the file content, not the file name. A zip file can contain several reports; every `.xml` member is imported on its own, and other members are ignored. Directory imports pick up `*.xml`, `*.gz`, and `*.zip`.

Anyone can send a report to a `rua` address, so decompression is limited to 64 MiB per report, and a zip member that is larger than its declared size is rejected. Encrypted and zip64 archives are not supported.

## Design

dmarcery is an audit and anomaly-detection database, not a mail-delivery log. Aggregate reports contain no message bodies or recipients, only authentication observations that receiving mail providers aggregated.

### Database rules

1. Raw reports are immutable. An imported XML report is never changed.
2. Imports are idempotent. The same report can be imported any number of times.
3. Observed facts stay observed facts. Historic observations are never rewritten when the sender registry changes.
4. Sender classification is independent metadata. Observed data (what reports said) and configured data (what we declare legitimate) are kept apart, and the importer never decides legitimacy.
5. Counts stay aggregated. A record with `count=500` is one row that represents 500 messages.
6. All authentication results are kept. Multiple DKIM signatures per record are normal and stay separately queryable.
7. The database can always be rebuilt from the archived XML (`dmarc rebuild`).
8. Migrations are versioned in `schema_migrations`, and the CLI applies them.

The receiver's `policy_evaluated` result is the authoritative DMARC state of a record. It is never recalculated or overwritten.

### Import protocol

1. Validate: reject files that are not DMARC aggregate reports.
2. Fingerprint: calculate the SHA-256 of the report XML, and check it and the reporter and report ID for duplicates. An already imported report is a success, not an error, so bulk imports are safe.
3. Preserve: copy the XML into the archive before the database changes.
4. Store: insert the report, records, DKIM results, and SPF results in one SQLite transaction.
5. Analyse: compare the report with earlier reports (see [Import findings](#import-findings)). Findings are observations only.
6. Report: print a short summary. Normal imports stay quiet.

### Design notes

* `policy_evaluated/reason` can occur more than once per record, so reasons are stored in their own `policy_reasons` table.
* `first_seen` and `last_seen` for sender identifiers are calculated from observations when queried. They are not stored, so they cannot become out of date.
* `<version>` is optional, because some reporters leave it out. `<report_metadata>` and `<policy_published>` are required.
* Source fields that the CLI does not use yet are stored too, for example `extra_contact_info`, `report_errors`, and `policy_fo`.
* The checksum covers the report XML, so the same report imported as `.xml`, `.gz`, or `.zip` counts as one report.

## Development

```bash
npm run check            # all read-only quality gates
npm run check:biome:fix  # apply Biome formatting and safe fixes
npm run lint:markdown:fix
npm test                 # node:test, runs TypeScript directly
npm run build            # compile to dist/
npm run release:dry      # preview the next release
```

The pre-commit hook (`simple-git-hooks` and `lint-staged`) runs Biome, markdownlint, and secretlint on staged files.
