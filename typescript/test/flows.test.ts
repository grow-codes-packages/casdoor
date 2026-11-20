import { afterEach, describe, expect, it } from "vitest";
import {
  AuthenticationError,
  CasdoorClient,
  CasdoorReason,
  ConfigError,
  EmailNotVerifiedError,
  MfaRequiredError,
  NotFoundError,
  RateLimitError,
  ValidationError,
  casdoorReason,
  createPkce,
  pkceChallenge,
  randomState,
  totpCode,
} from "../src/index.js";
import { decodeJwtPayload, userNameFor } from "../src/pkce.js";
import { toTokenSet } from "../src/user-flows.js";
import { type FakeCasdoor, startFakeCasdoor } from "./helpers/fake-casdoor.js";
import { type MockServer, startServer } from "./helpers/server.js";

const fakes: FakeCasdoor[] = [];
const servers: MockServer[] = [];
const clients: CasdoorClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(fakes.splice(0).map((f) => f.close()));
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function setup(
  extra: Record<string, unknown> = {},
): Promise<{ f: FakeCasdoor; c: CasdoorClient }> {
  const f = await startFakeCasdoor();
  fakes.push(f);
  const c = new CasdoorClient({
    url: f.url,
    publicUrl: "https://auth.example.test",
    clientId: "cid",
    clientSecret: "csecret",
    organization: "acme",
    application: "app-acme",
    redirectUri: "https://app.test/cb",
    retry: { maxRetries: 0 },
    ...extra,
  });
  clients.push(c);
  return { f, c };
}

function addUser(f: FakeCasdoor, name: string, extra: Record<string, unknown> = {}): void {
  f.users.set(`acme/${name}`, {
    owner: "acme",
    name,
    email: `${name}@acme.test`,
    password: "Password-123",
    emailVerified: true,
    ...extra,
  });
}

describe("sign-up, sign-in, refresh, sign-out", () => {
  it("signs up, verifies the e-mail and signs in", async () => {
    const { f, c } = await setup();
    const r = await c.signUp({
      email: "new.user@acme.test",
      password: "Password-123",
      displayName: "New",
    });
    expect(r).toEqual({ userId: "acme/new-user", organization: "acme", name: "new-user" });
    await expect(
      c.signIn({ username: "new.user@acme.test", password: "Password-123" }),
    ).rejects.toBeInstanceOf(EmailNotVerifiedError);
    await c.sendEmailVerification("new.user@acme.test");
    const code = f.mails.get("new.user@acme.test") ?? "";
    await expect(
      c.verifyEmail({ email: "new.user@acme.test", code: "000000" }),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await c.verifyEmail({ email: "new.user@acme.test", code });
    await c.verifyEmail({ email: "new.user@acme.test", code });
    expect(f.users.get("acme/new-user")?.emailVerified).toBe(true);
    const tokens = await c.signIn({ username: "new.user@acme.test", password: "Password-123" });
    expect(tokens.tokenType).toBe("Bearer");
    expect(tokens.refreshToken).toBeDefined();
    expect(tokens.expiresAt).toBeInstanceOf(Date);
    expect(decodeJwtPayload(tokens.accessToken)?.name).toBe("new-user");
  });

  it("signs up with an e-mail code and returns the fallback id", async () => {
    const { f, c } = await setup({ requireVerifiedEmail: false });
    await c.sendEmailVerification("code.user@acme.test", { purpose: "signup" });
    const r = await c.signUp({
      username: "code_user",
      email: "code.user@acme.test",
      password: "Password-123",
      emailCode: f.mails.get("code.user@acme.test") ?? "",
    });
    expect(r.userId).toBe("acme/code_user");
    const s = await startServer([{ body: { status: "ok", data: "Affected" } }]);
    servers.push(s);
    const c2 = new CasdoorClient({ url: s.url, organization: "o", application: "a" });
    clients.push(c2);
    expect((await c2.signUp({ email: "x@y.z", password: "p" })).userId).toBe("o/x");
  });

  it("rejects a wrong password and maps the Casdoor code", async () => {
    const { f, c } = await setup();
    addUser(f, "alice");
    const err = await c.signIn({ username: "alice", password: "nope" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthenticationError);
    expect(casdoorReason(err)).toBe(CasdoorReason.InvalidCredentials);
    expect((err as { casdoorCode?: string }).casdoorCode).toBe("wrong-password");
  });

  it("validates input client-side (no 'Phone number is invalid')", async () => {
    const { c } = await setup();
    await expect(c.signIn({ username: "alice", password: "" })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(c.signUp({ email: "a@b.c", password: " " })).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(c.refresh("")).rejects.toBeInstanceOf(ValidationError);
    await expect(c.signOut("")).rejects.toBeInstanceOf(ValidationError);
    await expect(
      c.resetPassword({ email: "a@b.c", code: "1", newPassword: "" }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("needs a redirect URI and the organization", async () => {
    const { c, f } = await setup({ redirectUri: undefined });
    await expect(c.signIn({ username: "a", password: "b" })).rejects.toBeInstanceOf(ConfigError);
    const c2 = new CasdoorClient({ url: f.url, clientId: "cid" });
    clients.push(c2);
    await expect(c2.signUp({ email: "a@b.c", password: "p" })).rejects.toThrow(/organization/);
    const c3 = new CasdoorClient({ url: f.url, organization: "acme" });
    clients.push(c3);
    await expect(c3.signUp({ email: "a@b.c", password: "p" })).rejects.toThrow(/application/);
  });

  it("refreshes and signs out", async () => {
    const { f, c } = await setup();
    addUser(f, "bob");
    const t = await c.signIn({
      username: "bob",
      password: "Password-123",
      redirectUri: "https://app.test/cb",
    });
    const t2 = await c.refresh(t.refreshToken ?? "");
    expect(t2.accessToken).not.toBe(t.accessToken);
    await expect(c.refresh(t.refreshToken ?? "")).rejects.toBeInstanceOf(AuthenticationError);
    await c.signOut(t2.accessToken);
    await c.signOut(t2.accessToken);
  });

  it("signOut rethrows non-authentication errors", async () => {
    const s = await startServer([{ body: { status: "error", msg: "Unauthorized operation" } }]);
    servers.push(s);
    const c = new CasdoorClient({ url: s.url, retry: { maxRetries: 0 } });
    clients.push(c);
    await expect(c.signOut("t")).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("reports a missing code or token", async () => {
    const s = await startServer((req) =>
      req.url.startsWith("/api/login?")
        ? { body: { status: "ok", data: null } }
        : { body: { token_type: "Bearer" } },
    );
    servers.push(s);
    const c = new CasdoorClient({
      url: s.url,
      clientId: "cid",
      organization: "o",
      application: "a",
      redirectUri: "r",
      retry: { maxRetries: 0 },
    });
    clients.push(c);
    await expect(c.signIn({ username: "a", password: "b" })).rejects.toThrow(
      /no authorization code/,
    );
    await expect(c.refresh("rt")).rejects.toThrow(/no access_token/);
  });
});

describe("authorize URL and code exchange", () => {
  it("builds the URL on the public origin and exchanges the code", async () => {
    const { f, c } = await setup();
    addUser(f, "carol");
    const pkce = createPkce();
    expect(pkce.codeChallenge).toBe(pkceChallenge(pkce.codeVerifier));
    expect(pkce.codeChallengeMethod).toBe("S256");
    const state = randomState();
    const url = new URL(
      c.buildAuthorizeUrl({
        redirectUri: "https://app.test/cb",
        state,
        codeChallenge: pkce.codeChallenge,
        nonce: "n1",
        extra: { prompt: "login" },
      }),
    );
    expect(url.origin).toBe("https://auth.example.test");
    expect(url.pathname).toBe("/login/oauth/authorize");
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("openid profile email");
    expect(url.searchParams.get("prompt")).toBe("login");
    expect(() => c.buildAuthorizeUrl({ redirectUri: "", state, codeChallenge: "x" })).toThrow(
      ValidationError,
    );
    // Simulate the browser leg: Casdoor issues a code bound to the challenge.
    const res = await fetch(
      `${f.url}/api/login?clientId=cid&responseType=code&redirectUri=x&code_challenge=${pkce.codeChallenge}`,
      {
        method: "POST",
        body: JSON.stringify({ organization: "acme", username: "carol", password: "Password-123" }),
      },
    );
    const code = ((await res.json()) as { data: string }).data;
    await expect(
      c.exchangeCode({ code, codeVerifier: "wrong-verifier", redirectUri: "https://app.test/cb" }),
    ).rejects.toBeInstanceOf(AuthenticationError);
    const res2 = await fetch(
      `${f.url}/api/login?clientId=cid&responseType=code&redirectUri=x&code_challenge=${pkce.codeChallenge}`,
      {
        method: "POST",
        body: JSON.stringify({ organization: "acme", username: "carol", password: "Password-123" }),
      },
    );
    const code2 = ((await res2.json()) as { data: string }).data;
    const t = await c.exchangeCode({
      code: code2,
      codeVerifier: pkce.codeVerifier,
      redirectUri: "https://app.test/cb",
    });
    expect(t.accessToken).toContain(".");
  });

  it("maps a bad client secret", async () => {
    const { c } = await setup({ clientSecret: "wrong-secret" });
    const err = await c
      .exchangeCode({ code: "x", codeVerifier: "y", redirectUri: "z" })
      .catch((e: unknown) => e);
    expect(casdoorReason(err)).toBe(CasdoorReason.InvalidClient);
  });
});

describe("e-mail verification and password reset", () => {
  it("rate limits codes and falls back to signup for new addresses", async () => {
    const { f, c } = await setup();
    await c.sendEmailVerification("fresh@acme.test");
    expect(f.mails.has("fresh@acme.test")).toBe(true);
    const err = await c.sendEmailVerification("fresh@acme.test").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RateLimitError);
    expect((err as RateLimitError).retryAfterMs).toBe(60_000);
    await expect(
      c.sendEmailVerification("other@acme.test", { purpose: "verify" }),
    ).rejects.toBeInstanceOf(NotFoundError);
    addUser(f, "dup");
    await expect(
      c.sendEmailVerification("dup@acme.test", { purpose: "signup" }),
    ).rejects.toMatchObject({
      code: "CONFLICT",
    });
  });

  it("verifyEmail needs an existing user", async () => {
    const { f, c } = await setup();
    await c.sendEmailVerification("ghost@acme.test", { purpose: "signup" });
    await expect(
      c.verifyEmail({ email: "ghost@acme.test", code: f.mails.get("ghost@acme.test") ?? "" }),
    ).rejects.toThrow(/sign up with emailCode/);
  });

  it("resets a forgotten password in one Casdoor session", async () => {
    const { f, c } = await setup();
    addUser(f, "dave");
    await c.forgotPassword("dave@acme.test");
    const code = f.mails.get("dave@acme.test") ?? "";
    await expect(
      c.resetPassword({ email: "dave@acme.test", code: "999999", newPassword: "New-Password-456" }),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await c.resetPassword({ email: "dave@acme.test", code, newPassword: "New-Password-456" });
    await expect(c.signIn({ username: "dave", password: "Password-123" })).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    expect(
      (await c.signIn({ username: "dave", password: "New-Password-456" })).accessToken,
    ).toBeTruthy();
    await expect(c.forgotPassword("nobody@acme.test")).rejects.toBeInstanceOf(NotFoundError);
    await expect(
      c.resetPassword({ email: "nobody@acme.test", code, newPassword: "x-123456789" }),
    ).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe("TOTP", () => {
  it("enrolls, then sign-in needs the second factor", async () => {
    const { f, c } = await setup();
    addUser(f, "erin");
    const t = await c.signIn({ username: "erin", password: "Password-123" });
    await expect(c.setupTotp(t.accessToken)).rejects.toThrow(/not allowed by the MFA items/);
    (f.orgs.get("admin/acme") as Record<string, unknown>).mfaItems = [
      { name: "app", rule: "Optional" },
    ];
    const setup1 = await c.setupTotp(t.accessToken);
    expect(setup1.recoveryCodes).toEqual(["rc-1"]);
    await expect(
      c.verifyTotp({
        accessToken: t.accessToken,
        secret: setup1.secret,
        code: "000000",
        recoveryCode: "rc-1",
      }),
    ).rejects.toBeInstanceOf(Error);
    expect(f.users.get("acme/erin")?.totpSecret).toBeUndefined();
    await c.verifyTotp({
      accessToken: t.accessToken,
      secret: setup1.secret,
      code: totpCode(setup1.secret),
      recoveryCode: "rc-1",
    });
    const err = await c
      .signIn({ username: "erin", password: "Password-123" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MfaRequiredError);
    expect((err as MfaRequiredError).mfaTypes).toEqual(["app"]);
    expect(casdoorReason(err)).toBe(CasdoorReason.MfaRequired);
    const ok = await c.signIn({
      username: "erin",
      password: "Password-123",
      totpCode: totpCode(setup1.secret),
    });
    expect(ok.accessToken).toBeTruthy();
    const rec = await c.signIn({
      username: "erin",
      password: "Password-123",
      recoveryCode: "rc-1",
    });
    expect(rec.accessToken).toBeTruthy();
    await expect(
      c.signIn({ username: "erin", password: "Password-123", totpCode: "000000" }),
    ).rejects.toBeInstanceOf(Error);
  });

  it("needs a JWT access token with owner/name", async () => {
    const { c } = await setup();
    await expect(c.setupTotp("opaque-token")).rejects.toThrow(/owner\/name/);
  });

  it("reports a missing secret", async () => {
    const s = await startServer([{ body: { status: "ok", data: {} } }]);
    servers.push(s);
    const c = new CasdoorClient({ url: s.url, retry: { maxRetries: 0 } });
    clients.push(c);
    const token = `x.${Buffer.from(JSON.stringify({ owner: "o", name: "n" })).toString("base64url")}.y`;
    await expect(c.setupTotp(token)).rejects.toThrow(/no TOTP secret/);
  });
});

describe("pure helpers", () => {
  it("totpCode matches RFC 6238 test vector", () => {
    // RFC 6238 SHA-1 vector: secret "12345678901234567890", T=59 → 94287082 (8 digits) → 287082.
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    expect(totpCode(secret, new Date(59_000))).toBe("287082");
    expect(() => totpCode("!!!")).toThrow(TypeError);
  });

  it("decodes JWT payloads and derives user names", () => {
    expect(decodeJwtPayload("abc")).toBeUndefined();
    expect(decodeJwtPayload("a.!!!.c")).toBeUndefined();
    expect(decodeJwtPayload(`a.${Buffer.from("1").toString("base64url")}.c`)).toBeUndefined();
    expect(userNameFor("john.doe@x.test")).toBe("john-doe");
    expect(userNameFor("x@y", "valid_name")).toBe("valid_name");
    expect(userNameFor("@y")).toBe("user");
  });

  it("toTokenSet keeps optional fields", () => {
    const t = toTokenSet({ access_token: "a", expires_in: 0, scope: "openid" }, 0);
    expect(t).toEqual({ accessToken: "a", tokenType: "Bearer", scope: "openid" });
  });
});
