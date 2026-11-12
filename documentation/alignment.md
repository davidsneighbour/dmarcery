# Alignment comparison

`dmarc alignment` optionally compares the receiver's reported DKIM and SPF alignment with a recalculation from the authentication observations stored in aggregate reports. It lists definite mismatches by default. This check never changes records, archived XML, sender classifications, existing views, summary totals, or import findings.

```bash
dmarc alignment
dmarc alignment --days 30 --domain example.com
dmarc alignment --reporter receiver.example --json
dmarc alignment --all        # include matches and unknown results
```

`--data-dir` and `DMARC_HOME` select the database as usual. Filters have the same meanings as the other inspection commands: `--days` compares report end times with the current time, `--domain` selects the published policy domain, and `--reporter` selects the reporting organisation. Without a time filter, all stored reports are checked. A successful query exits with status 0 even if it finds mismatches. A mismatch is an observation for review, not an import error or a change to a sender's legitimacy.

## Comparison rules

DKIM passes the recalculation when at least one stored DKIM result is `pass` and its signing domain aligns with `header_from`. SPF uses passing MAIL FROM authentication domains, rather than treating a passing HELO result as sufficient. Authentication results that fail do not establish alignment, even if their domain matches.

Each mechanism uses its published alignment policy: `adkim` for DKIM and `aspf` for SPF. A missing policy mode defaults to relaxed alignment. Strict mode (`s`) requires an exact domain match after case, trailing-root-dot, and IDNA normalisation. Relaxed mode (`r`) compares organisational domains using the bundled Public Suffix List (PSL). This handles multi-label public suffixes such as `co.uk`, wildcard rules, and exceptions; it is not a last-two-label comparison. ICANN and private suffixes are included, so unrelated tenants such as `one.github.io` and `two.github.io` do not align. Public suffixes alone cannot establish relaxed alignment. IP literals, URLs, email addresses, and malformed domain names do not count as domain evidence.

The combined recalculated result is `pass` when either mechanism passes, `fail` when both fail, and `unknown` otherwise. A mismatch is listed when a definite recalculated mechanism differs from the corresponding reported `pass` or `fail`, even if the other mechanism makes overall DMARC pass. Missing reported evaluations are not silently interpreted as reported failures for comparison purposes; the existing `v_records.dmarc_result` remains unchanged and is also present in JSON output.

JSON returns each record's report ID, record ID, date, reporter, policy domain, header-from domain, source IP, message count, published modes, reported evaluations, recalculated evaluations, mismatch flag, differing mechanisms, explanatory notes, and method (`rfc7489-psl`). The table shows the reported and checked values side by side. With `--all`, records with insufficient evidence remain visible as `unknown`; a default empty result therefore does not mean that every stored record could be verified.

## Missing evidence and limitations

Reports can omit authentication results, domain names, alignment modes, or SPF scope. Missing authentication results, invalid domains on passing results, invalid policy modes, and unrecognised authentication results produce `unknown` when no known aligned pass is available. This avoids declaring definite mismatches from incomplete evidence. Omitted SPF scope is treated as MAIL FROM for compatibility with older reports; an explanatory note accompanies that assumption. HELO-only evidence remains unknown because stored aggregate observations do not reliably distinguish an omitted envelope-from from an empty reverse-path. A known aligned pass can still establish a combined pass when the other mechanism is unknown.

This implements the offline PSL-based comparison requested in [issue #3](https://github.com/davidsneighbour/dmarcery/issues/3), based on [RFC 7489 alignment](https://www.rfc-editor.org/rfc/rfc7489#section-3.1). [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10) supersedes that standard and determines organisational domains using a DNS tree walk. This command does not perform that tree walk, DNS lookups, DKIM signature verification, or SPF authorisation checks. It trusts only the stored authentication outcomes for its calculation, and it does not claim to reproduce every historical receiver decision. Differences can reflect reporting omissions, receiver behaviour, private-suffix handling, historical PSL changes, or differences between protocol versions.

## Suffix data and updates

`tldts` version `7.5.0` supplies the PSL snapshot in the pinned runtime dependency; its parser dependencies are fixed by `package-lock.json`. There are no suffix-list downloads during an import or a check. See the [upstream library documentation](https://github.com/remusao/tldts) for its PSL handling.

Update the snapshot deliberately by selecting a reviewed `tldts` release, installing it with `npm install --save-exact tldts@NEW_VERSION`, updating this documented version, and committing both package files. Run `npm run check` and `npm run build` before committing. Rerun comparisons after an update: a newer PSL can change recalculated results, while the receiver's stored observations remain immutable. `npm ci` reproduces the locked parser versions and bundled snapshot. No recalculated values are cached or written back to the database, so `dmarc rebuild` requires no extra alignment state.
