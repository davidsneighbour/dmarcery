import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { loadGmailConfig, READONLY_SCOPE } from "../src/gmail.ts";
import {
  authoriseGmail,
  loadGoogleClient,
  saveGmailConfig,
} from "../src/gmail-auth.ts";
import { temporaryPaths, writeFixture } from "./helpers.ts";

const client = { clientId: "example-client", clientSecret: "example-secret" };
const account = "you@example.com";

test("browser flow uses PKCE, rejects incorrect state, and saves a separate token securely", async (t) => {
  const realFetch = globalThis.fetch;
  let challenge = "";
  t.mock.method(
    globalThis,
    "fetch",
    async (input: string, init?: RequestInit) => {
      if (String(input).startsWith("http://127.0.0.1:"))
        return realFetch(input, init);
      if (input === "https://oauth2.googleapis.com/token") {
        assert.equal(init?.method, "POST");
        const body = init?.body as URLSearchParams;
        assert.equal(body.get("code"), "example-code");
        assert.equal(
          createHash("sha256")
            .update(body.get("code_verifier") ?? "")
            .digest("base64url"),
          challenge,
        );
        return Response.json({
          access_token: "example-access",
          refresh_token: "new-dmarc-token",
          scope: READONLY_SCOPE,
        });
      }
      assert.equal(
        input,
        "https://gmail.googleapis.com/gmail/v1/users/me/profile",
      );
      assert.notEqual(init?.method, "POST");
      return Response.json({ emailAddress: account });
    },
  );
  const token = await authoriseGmail(client, account, async (url) => {
    const auth = new URL(url);
    assert.equal(auth.origin, "https://accounts.google.com");
    assert.equal(auth.searchParams.get("scope"), READONLY_SCOPE);
    assert.equal(auth.searchParams.get("include_granted_scopes"), "false");
    assert.equal(auth.searchParams.get("code_challenge_method"), "S256");
    challenge = auth.searchParams.get("code_challenge") ?? "";
    const callback = new URL(auth.searchParams.get("redirect_uri") ?? "");
    callback.searchParams.set("state", "wrong");
    callback.searchParams.set("code", "example-code");
    assert.equal((await realFetch(callback)).status, 400);
    callback.searchParams.set("state", auth.searchParams.get("state") ?? "");
    assert.equal((await realFetch(callback)).status, 200);
  });
  assert.equal(token, "new-dmarc-token");
  const paths = temporaryPaths();
  const original = writeFixture(
    paths.dataDir,
    "client_secret.json",
    JSON.stringify({
      installed: {
        client_id: client.clientId,
        client_secret: client.clientSecret,
      },
    }),
  );
  const before = readFileSync(original);
  assert.deepEqual(loadGoogleClient(original), client);
  const config = join(paths.dataDir, "dmarc", "gmail.json");
  saveGmailConfig(config, client, account, ["reports@example.com"], token);
  assert.equal(statSync(config).mode & 0o777, 0o600);
  assert.equal(loadGmailConfig(config).refreshToken, "new-dmarc-token");
  assert.deepEqual(readFileSync(original), before);
});

test("browser flow stops on denial and timeout without saving credentials", async () => {
  await assert.rejects(
    authoriseGmail(client, account, async (url) => {
      const auth = new URL(url);
      const callback = new URL(auth.searchParams.get("redirect_uri") ?? "");
      callback.searchParams.set("state", auth.searchParams.get("state") ?? "");
      callback.searchParams.set("error", "access_denied");
      await fetch(callback);
    }),
    /declined/,
  );
  await assert.rejects(
    authoriseGmail(client, account, async () => {}, 10),
    /timed out/,
  );
});

test("browser flow rejects broad grants and the wrong mailbox", async (t) => {
  const realFetch = globalThis.fetch;
  let broad = true;
  t.mock.method(
    globalThis,
    "fetch",
    async (input: string, init?: RequestInit) => {
      if (String(input).startsWith("http://127.0.0.1:"))
        return realFetch(input, init);
      if (input === "https://oauth2.googleapis.com/token")
        return Response.json({
          access_token: "example-access",
          refresh_token: "example-refresh",
          scope: broad ? "https://mail.google.com/" : READONLY_SCOPE,
        });
      return Response.json({ emailAddress: "other@example.com" });
    },
  );
  const callback = async (url: string) => {
    const auth = new URL(url);
    const redirect = new URL(auth.searchParams.get("redirect_uri") ?? "");
    redirect.searchParams.set("state", auth.searchParams.get("state") ?? "");
    redirect.searchParams.set("code", "example-code");
    await realFetch(redirect);
  };
  await assert.rejects(
    authoriseGmail(client, account, callback),
    /gmail.readonly offline token/,
  );
  broad = false;
  await assert.rejects(
    authoriseGmail(client, account, callback),
    /does not match/,
  );
});
