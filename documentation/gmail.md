# Manual mailbox import

`dmarc import` without file arguments reads Gmail. File and directory imports keep their existing behaviour. This feature uses Node's built-in fetch and SQLite support and a pinned TOML parser. It adds no background jobs.

## Configure mailboxes

The default settings file is `~/.config/dmarcery.toml`. Copy [the example configuration](dmarcery.example.toml) there and replace its example addresses:

```toml
[gmail]
client_file = "~/.msgvault/client_secret.json"
senders = ["noreply-dmarc-support@google.com"]

[[gmail.accounts]]
address = "first@example.com"

[[gmail.accounts]]
address = "second@example.com"
# Optional: replace the shared sender list for this mailbox.
# senders = ["noreply-dmarc-support@google.com", "reports@example.net"]
```

Each `[[gmail.accounts]]` table is one Gmail mailbox to read. The `senders` array lists reporting addresses to discover, not your own mailboxes. Add any number of mailboxes and sender addresses. Addresses are normalised to lower case; duplicate mailbox addresses, empty sender lists, invalid addresses, unknown options, and malformed TOML are rejected before mailbox processing begins. Addresses must be plain email addresses, with letters, numbers, dots, underscores, percent signs, plus signs, or hyphens in the local part. From headers can be forged, so the allowlist is a discovery filter, not proof of authenticity.

`gmail.senders` supplies the shared sender allowlist. An account's `senders` array replaces that list. `gmail.client_file` defaults to `~/.msgvault/client_secret.json`; an account's `client_file` can override it. Paths in TOML support `~/` and absolute paths. Relative client paths resolve against the TOML file's directory. Use `--config /absolute/path/to/settings.toml` with sign-in, import, dry run, or review to select another settings file.

The TOML file contains addresses and client-file paths only. Refresh tokens stay in separate mode-0600 files under `DATA_DIR/gmail-credentials/`, named by the SHA-256 of each normalised account address. `DATA_DIR` defaults to `~/.local/share/dmarc`; `--data-dir` and `DMARC_HOME` select another directory for credentials, tracking, and report data. Use the same data directory for sign-in and import. Do not put OAuth tokens or client secrets in the TOML file.

## Set up access

After configuring the mailboxes, sign in through your browser:

```bash
dmarc gmail-auth                           # sign in to each configured mailbox
dmarc gmail-auth --account first@example.com # sign in to one mailbox
```

Each mailbox receives a separate DMARC token. The command opens your browser with `xdg-open` and also prints the sign-in URL. If automatic opening fails, open that URL on the same computer within five minutes. It uses a random loopback port, a random state value, and PKCE. It requests only `gmail.readonly`, checks the selected account, and saves credentials only after successful authorisation. Running it again replaces credentials only for the selected mailboxes and does not edit your TOML file or another mailbox's credentials. A failed sign-in leaves that mailbox's previous credential file unchanged, reports the error, and continues with the next mailbox. `--gmail-client FILE` overrides the client-file setting for that sign-in.

Only the application's `installed` client ID and client secret are read from msgvault. The command never reads, copies, or changes anything in `~/.msgvault/tokens/`. Initial consent and account selection happen in Google's browser interface; dmarc never collects your account password. Changing sender settings takes effect on the next import without signing in again. Changing an account address or its Google client requires a new sign-in.

Reusing a client means sharing the Google app identity, consent configuration, and token issuance limits. Separate local tokens do not provide separate app revocation: removing the shared app grant in Google can affect msgvault as well. The CLI does not revoke grants automatically. For isolation at Google too, create a separate Desktop app client, then select it with `--gmail-client`. See Google's [Desktop app flow](https://developers.google.com/identity/protocols/oauth2/native-app).

For a new app, enable the Gmail API in its Google Cloud project, configure the consent screen, add your account as a test user if applicable, and download a **Desktop app** client JSON file. External applications in testing can have short-lived refresh tokens; an expired or revoked grant requires a new sign-in. Workspace policies can also block access.

The CLI refreshes access tokens each time you run an import. Never commit credentials or paste them into logs. Back up the private credential directory separately from the public TOML settings. The account address must match Gmail's primary profile email address; mailbox aliases are not separate Google accounts.

### Earlier single-account configuration

The earlier JSON configuration remains supported with an explicit `--gmail-config /absolute/path/to/gmail.json`. That option selects one legacy mailbox and cannot be combined with `--config`. Existing files are not migrated or deleted. To adopt TOML, add your mailbox addresses and run `gmail-auth` to obtain new credentials in the separate per-account files. Legacy sign-in with `--account EMAIL --gmail-sender EMAIL` still writes the earlier JSON format; prefer TOML for new setups. The `--json` result format has changed: import results are now grouped by account, including for legacy configurations.

## Run and review

```bash
dmarc import --dry-run       # fetch and validate; no persistent local changes
dmarc import                 # import all configured mailboxes manually; no schedule
dmarc import --review        # print saved successful-message links; no network access
dmarc import --json          # results grouped by mailbox as JSON
dmarc import --account first@example.com # import only this configured mailbox
```

`--dry-run` and `--review` apply only to Gmail imports and cannot be combined. Global `--data-dir` and `DMARC_HOME` still work. Dry runs validate every downloaded report, including identity conflicts against existing data and earlier reports in the same run. They do not import reports, write archives, save tracking, or produce deletion review links. The CLI uses a temporary database copy and removes it on completion; forced termination can leave that temporary copy in the system temporary directory.

Discovery pages through the sender allowlist query with `has:attachment`. Gmail's default search excludes Spam and Trash. Each message's From address is checked again before attachments are downloaded. Nested MIME parts, inline attachment data, and separately fetched attachments are supported. Every attachment is required to contain valid XML, gzip, or zip DMARC data; an unrelated attachment blocks the whole message from review. Within a zip, the existing extractor imports XML members and ignores other members. Encoded responses, input attachments, decompressed reports, and combined zip contents have size limits.

A message is complete only when every attachment succeeds. Exact duplicate XML is successful; an existing reporter/report ID with different XML is a conflict. Successful reports from a partially failed message remain imported, but the message receives no review link. The next run retries failed attachments and skips successful attachments whose XML checksums still exist in the report database. There are no automatic retries for HTTP errors: rerun the command after resolving connectivity, rate limits, or authorisation problems. Runs longer than an access token's lifetime may need to be rerun.

The summary groups Gmail message IDs, statuses, successful attachment counts, errors, and individual review links by mailbox. Exit status is 1 if any message or mailbox fails. Discovery, missing credentials, or authorisation failures stop that mailbox and allow the remaining mailboxes to continue. Completed work remains safe to retry; `--review` retrieves saved complete messages if an interrupted discovery prevented their summary from being returned. No matches is a successful empty result. `--account EMAIL` restricts sign-in, import, dry run, and review to one configured address; an unknown address is an error. Without it, all configured mailboxes are processed sequentially.

Review links use the account and exact Gmail message ID, never a broad sender search. `--review` repeats all saved complete messages, including earlier runs, after checking that their report checksums are still present. It needs only the configured account addresses and local databases, not OAuth credentials or network access. It does not check whether a message still exists remotely. Gmail's web URL format is not an API contract and has not been verified against a live mailbox. Gmail can display surrounding conversation messages: inspect the selected message and attachments before manually deleting anything, and avoid deleting a whole conversation that contains other mail. The CLI never opens links or performs deletion.

## Local state and security

Gmail API requests use GET only. The only POST requests are OAuth code exchanges and token refreshes at Google's fixed token endpoint. The CLI rejects grants unless the returned scope is exactly `gmail.readonly`, and checks the mailbox profile before searching. Gmail's [scope documentation](https://developers.google.com/workspace/gmail/api/auth/scopes) describes this as read access to the mailbox; the sender allowlist does not restrict what the OAuth credential itself can read. There are no API calls for deleting, archiving, labelling, marking messages read, or changing any Gmail state.

`gmail.sqlite` in the data directory stores account/message/part identities, report checksums, completion state, and attachment failures. It is separate from the rebuildable report database, has file mode 0600, and survives `dmarc rebuild`. Back it up with the report database and archive. Losing it causes attachment downloads to repeat; existing XML fingerprint checks still prevent duplicate report rows. Tracking is written only after report import; a crash between these steps safely results in duplicate detection on retry. Review checks the current database, so reports missing after an incomplete rebuild do not qualify. Do not run imports and rebuild concurrently.

Attachments stay in memory; only validated XML is archived through the existing pipeline. Archive names are sanitised, and remote attachment names are never used as download paths. OAuth access tokens remain in memory and are never stored in the tracking database. Refresh tokens are local secrets in the per-account credential files (or the explicitly selected legacy JSON file); remove the relevant credential file when no longer required. Revoke a dedicated application grant in your Google account if appropriate; revoking the shared msgvault app grant can affect both tools. No live mailbox verification is part of the automated test suite.
