import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { dirname } from "node:path";
import { READONLY_SCOPE } from "./gmail.ts";

export interface GoogleClient {
  clientId: string;
  clientSecret: string;
}

/** Reads application credentials only, never msgvault account tokens. */
export function loadGoogleClient(path: string): GoogleClient {
  const file = JSON.parse(readFileSync(path, "utf8")) as {
    installed?: { client_id?: string; client_secret?: string };
  };
  if (!file.installed?.client_id || !file.installed.client_secret)
    throw new Error("Select a Google Desktop app client_secret.json file");
  return {
    clientId: file.installed.client_id,
    clientSecret: file.installed.client_secret,
  };
}

/** Separate offline grant with PKCE and a short-lived, loopback-only callback. */
export async function authoriseGmail(
  client: GoogleClient,
  account: string,
  showUrl: (url: string) => Promise<void>,
  timeoutMs = 300_000,
): Promise<string> {
  const state = randomBytes(32).toString("base64url");
  const verifier = randomBytes(32).toString("base64url");
  let finish: (code: string) => void = () => {};
  let fail: (error: Error) => void = () => {};
  const codePromise = new Promise<string>((resolve, reject) => {
    finish = resolve;
    fail = reject;
  });
  // Attach a rejection handler before browser launch to avoid an unhandled denial.
  void codePromise.catch(() => {});
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Content-Type", "text/plain; charset=utf-8");
    if (
      request.method !== "GET" ||
      url.pathname !== "/oauth2callback" ||
      url.searchParams.get("state") !== state
    ) {
      response.writeHead(400).end("Invalid authorisation callback.");
      return;
    }
    const code = url.searchParams.get("code");
    if (url.searchParams.has("error") || !code) {
      response.end("Authorisation declined. Return to dmarc.");
      fail(new Error("Gmail authorisation declined"));
      return;
    }
    response.end(
      "Authorisation received. Return to dmarc to check the result.",
    );
    finish(code);
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Cannot start OAuth callback listener");
    const redirect = `http://127.0.0.1:${address.port}/oauth2callback`;
    const query = new URLSearchParams({
      client_id: client.clientId,
      redirect_uri: redirect,
      response_type: "code",
      scope: READONLY_SCOPE,
      access_type: "offline",
      prompt: "consent select_account",
      include_granted_scopes: "false",
      login_hint: account,
      state,
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
    });
    timer = setTimeout(
      () =>
        fail(new Error("Gmail authorisation timed out; run gmail-auth again")),
      timeoutMs,
    );
    await showUrl(`https://accounts.google.com/o/oauth2/v2/auth?${query}`);
    const code = await codePromise;
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
      body: new URLSearchParams({
        client_id: client.clientId,
        client_secret: client.clientSecret,
        code,
        code_verifier: verifier,
        redirect_uri: redirect,
        grant_type: "authorization_code",
      }),
    });
    if (!response.ok)
      throw new Error(`OAuth exchange failed (${response.status})`);
    const token = (await response.json()) as {
      access_token?: string;
      refresh_token?: string;
      scope?: string;
    };
    if (
      token.scope !== READONLY_SCOPE ||
      !token.access_token ||
      !token.refresh_token
    )
      throw new Error(
        "Expected a separate gmail.readonly offline token; no credentials saved",
      );
    const profileResponse = await fetch(
      "https://gmail.googleapis.com/gmail/v1/users/me/profile",
      {
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
        headers: { Authorization: `Bearer ${token.access_token}` },
      },
    );
    if (!profileResponse.ok)
      throw new Error(`Gmail profile check failed (${profileResponse.status})`);
    const profile = (await profileResponse.json()) as { emailAddress?: string };
    if (profile.emailAddress?.toLowerCase() !== account.toLowerCase())
      throw new Error(
        "Selected Gmail account does not match --account; no credentials saved",
      );
    return token.refresh_token;
  } finally {
    if (timer) clearTimeout(timer);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

export function saveGmailConfig(
  path: string,
  client: GoogleClient,
  account: string,
  senders: string[],
  refreshToken: string,
): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(
      temporary,
      `${JSON.stringify({ account: account.toLowerCase(), senders, ...client, refreshToken }, null, 2)}\n`,
      { mode: 0o600, flag: "wx" },
    );
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}
