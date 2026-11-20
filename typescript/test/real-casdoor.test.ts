// Integration test against a real Casdoor + Mailpit (skipped unless GROW_CASDOOR_IT_URL is set).
// Env: GROW_CASDOOR_IT_URL, GROW_CASDOOR_IT_ADMIN_PASSWORD, GROW_CASDOOR_IT_MAILPIT (Mailpit HTTP
// URL seen from the test), GROW_CASDOOR_IT_SMTP_HOST (Mailpit SMTP host seen from Casdoor).

import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AuthenticationError,
  CasdoorClient,
  EmailNotVerifiedError,
  MfaRequiredError,
  createPkce,
  randomState,
  totpCode,
} from "../src/index.js";
import { decodeJwtPayload } from "../src/pkce.js";

const URL_ = process.env.GROW_CASDOOR_IT_URL;
const MAILPIT = process.env.GROW_CASDOOR_IT_MAILPIT ?? "";

async function mailCode(to: string, after: number): Promise<string> {
  for (let i = 0; i < 60; i++) {
    const res = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`);
    const body = (await res.json()) as { messages?: { ID: string; Created: string }[] };
    const msg = (body.messages ?? []).find((m) => Date.parse(m.Created) >= after - 2000);
    if (msg !== undefined) {
      const full = (await (await fetch(`${MAILPIT}/api/v1/message/${msg.ID}`)).json()) as {
        Text: string;
      };
      const code = /\b(\d{6})\b/.exec(full.Text)?.[1];
      if (code !== undefined) return code;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`no mail for ${to}`);
}

describe.skipIf(URL_ === undefined)("real Casdoor", () => {
  it("runs every admin operation and user flow", { timeout: 120_000 }, async () => {
    const id = randomBytes(3).toString("hex");
    const org = `it-${id}`;
    const app = `app-it-${id}`;
    const redirect = "https://app.test/auth/callback";
    const common = {
      url: URL_,
      organization: org,
      application: app,
      clientId: `cid-${id}`,
      clientSecret: randomBytes(20).toString("hex"),
      redirectUri: redirect,
    };
    const admin = new CasdoorClient({
      ...common,
      adminPassword: process.env.GROW_CASDOOR_IT_ADMIN_PASSWORD ?? "",
    });
    try {
      expect((await admin.health()).healthy).toBe(true);
      expect(await admin.serverVersion()).toMatch(/^v\d/);
      expect(
        (await admin.ensureOrganization({ name: org, passwordOptions: ["AtLeast8"] })).created,
      ).toBe(true);
      expect(
        (await admin.ensureOrganization({ name: org, passwordOptions: ["AtLeast8"] })).created,
      ).toBe(false);
      const a = await admin.ensureApplication({ redirectUris: [redirect] });
      expect(a.created).toBe(true);
      expect(a.clientSecret).toBe(common.clientSecret);
      expect((await admin.ensureApplication({ redirectUris: [redirect] })).created).toBe(false);
      await admin.ensureEmailProvider({
        name: `provider-mail-${id}`,
        host: process.env.GROW_CASDOOR_IT_SMTP_HOST ?? "mailpit",
        port: 1025,
        from: `no-reply@${org}.test`,
        disableSsl: true,
      });
      expect((await admin.ensureRoles(["buyer", "seller"])).every((r) => r.created)).toBe(true);
      const buyerEmail = `buyer-${id}@example.test`;
      const u = await admin.ensureUser({
        email: buyerEmail,
        password: "Password-123",
        roles: ["buyer"],
      });
      expect(u.created).toBe(true);
      // existing user: new password through the full-object update
      expect(
        (await admin.ensureUser({ email: buyerEmail, password: "Password-456" })).created,
      ).toBe(false);
      await admin.assignRoles(buyerEmail, ["seller"]);
      expect(await admin.ping()).toBeGreaterThanOrEqual(0);
    } finally {
      await admin.close();
    }

    // The BFF client: client credentials only (no admin password).
    const c = new CasdoorClient(common);
    try {
      const buyerEmail = `buyer-${id}@example.test`;
      await expect(
        c.signIn({ username: buyerEmail, password: "Password-123" }),
      ).rejects.toBeInstanceOf(AuthenticationError);
      const t = await c.signIn({ username: buyerEmail, password: "Password-456" });
      const claims = decodeJwtPayload(t.accessToken) ?? {};
      expect(claims.aud).toEqual(expect.arrayContaining([common.clientId]));
      const roles = (claims.roles as { name: string }[]).map((r) => r.name).sort();
      expect(roles).toEqual(["buyer", "seller"]);
      const t2 = await c.refresh(t.refreshToken ?? "");
      expect(t2.accessToken).not.toBe(t.accessToken);
      await c.signOut(t2.accessToken);
      await c.signOut(t2.accessToken);

      // sign-up → unverified → verify by code → sign-in
      const newEmail = `new-${id}@example.test`;
      const r = await c.signUp({ email: newEmail, password: "Password-123", displayName: "New" });
      expect(r.userId).toBe(`${org}/new-${id}`);
      await expect(
        c.signIn({ username: newEmail, password: "Password-123" }),
      ).rejects.toBeInstanceOf(EmailNotVerifiedError);
      let since = Date.now();
      await c.sendEmailVerification(newEmail);
      await c.verifyEmail({ email: newEmail, code: await mailCode(newEmail, since) });
      expect(
        (await c.signIn({ username: newEmail, password: "Password-123" })).accessToken,
      ).toBeTruthy();

      // forgot / reset
      since = Date.now();
      await c.forgotPassword(buyerEmail);
      const code = await mailCode(buyerEmail, since);
      await c.resetPassword({ email: buyerEmail, code, newPassword: "Password-789" });
      const t3 = await c.signIn({ username: buyerEmail, password: "Password-789" });

      // TOTP
      const setup = await c.setupTotp(t3.accessToken);
      await c.verifyTotp({
        accessToken: t3.accessToken,
        secret: setup.secret,
        code: totpCode(setup.secret),
        recoveryCode: setup.recoveryCodes[0] ?? "",
      });
      await expect(
        c.signIn({ username: buyerEmail, password: "Password-789" }),
      ).rejects.toBeInstanceOf(MfaRequiredError);
      expect(
        (
          await c.signIn({
            username: buyerEmail,
            password: "Password-789",
            totpCode: totpCode(setup.secret),
          })
        ).accessToken,
      ).toBeTruthy();

      // authorize URL + code exchange (browser leg simulated with /api/login)
      const pkce = createPkce();
      const url = new URL(
        c.buildAuthorizeUrl({
          redirectUri: redirect,
          state: randomState(),
          codeChallenge: pkce.codeChallenge,
        }),
      );
      expect(url.pathname).toBe("/login/oauth/authorize");
      const q = new URLSearchParams({
        clientId: common.clientId,
        responseType: "code",
        redirectUri: redirect,
        scope: "openid",
        state: "s",
        code_challenge: pkce.codeChallenge,
        code_challenge_method: "S256",
      });
      const res = await fetch(`${URL_}/api/login?${q.toString()}`, {
        method: "POST",
        body: JSON.stringify({
          application: app,
          organization: org,
          username: newEmail,
          password: "Password-123",
          type: "code",
        }),
      });
      const browserCode = ((await res.json()) as { data: string }).data;
      const t4 = await c.exchangeCode({
        code: browserCode,
        codeVerifier: pkce.codeVerifier,
        redirectUri: redirect,
      });
      expect(t4.accessToken).toBeTruthy();
    } finally {
      await c.close();
    }
  });
});
