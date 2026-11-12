import type { MailAccount } from "./config.ts";
import type { Database } from "./db.ts";
import {
  type GmailReader,
  gmailReader,
  ingestGmail,
  loadGmailConfig,
} from "./gmail.ts";
import type { DataPaths } from "./paths.ts";

export interface MailMode {
  dryRun: boolean;
  review: boolean;
}
type ReaderFactory = (
  account: MailAccount,
  mode: MailMode,
) => Promise<GmailReader>;

export async function configuredReader(
  account: MailAccount,
  mode: MailMode,
): Promise<GmailReader> {
  if (mode.review)
    return {
      account: account.address,
      async *list() {
        yield* [];
      },
      async message(): Promise<never> {
        throw new Error("Review is offline");
      },
      async attachment(): Promise<never> {
        throw new Error("Review is offline");
      },
    };
  let credentials: ReturnType<typeof loadGmailConfig>;
  try {
    credentials = loadGmailConfig(account.credentialsFile);
  } catch {
    throw new Error(
      `Missing or invalid DMARC credentials for ${account.address}; run gmail-auth --account ${account.address}`,
    );
  }
  if (credentials.account !== account.address)
    throw new Error("Stored credentials belong to another Gmail account");
  return gmailReader({ ...credentials, senders: account.senders });
}

/** One failed mailbox must not prevent the remaining mailboxes from being read. */
export async function importMailAccounts(
  db: Database,
  paths: DataPaths,
  accounts: MailAccount[],
  mode: MailMode,
  createReader: ReaderFactory = configuredReader,
) {
  const outcomes: {
    account: string;
    messages: Awaited<ReturnType<typeof ingestGmail>>;
    error?: string;
  }[] = [];
  const dryIdentities = new Map<string, string>();
  for (const account of accounts) {
    try {
      const reader = await createReader(account, mode);
      if (reader.account.toLowerCase() !== account.address)
        throw new Error("Reader account does not match configuration");
      const messages = await ingestGmail(
        db,
        paths,
        reader,
        account.senders,
        mode.dryRun,
        mode.review,
        dryIdentities,
      );
      outcomes.push({ account: account.address, messages });
    } catch (error) {
      outcomes.push({
        account: account.address,
        messages: [],
        error: error instanceof Error ? error.message : "Mailbox import failed",
      });
    }
  }
  return outcomes;
}
