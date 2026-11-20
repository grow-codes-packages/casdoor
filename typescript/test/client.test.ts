import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  AuthenticationError,
  CasdoorClient,
  CasdoorConfig,
  CasdoorError,
  CasdoorReason,
  ConfigError,
  ConflictError,
  NotFoundError,
  PermissionDeniedError,
  RateLimitError,
  REDACTED,
  Secret,
  UnsupportedError,
  ValidationError,
  VENDOR_ENV,
  casdoorReason,
} from "../src/index.js";
import { envelopeError, maskedObjectError, oauthError } from "../src/casdoor-errors.js";
import { CookieJar, formBody } from "../src/casdoor-api.js";
import { ADMIN_PASSWORD, type FakeCasdoor, startFakeCasdoor } from "./helpers/fake-casdoor.js";
import { type MockServer, closedPort, startServer } from "./helpers/server.js";

const fakes: FakeCasdoor[] = [];
const servers: MockServer[] = [];
const clients: CasdoorClient[] = [];
afterEach(async () => {
  await Promise.all(clients.splice(0).map((c) => c.close()));
  await Promise.all(fakes.splice(0).map((f) => f.close()));
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

const fast = { retry: { maxRetries: 0, initialBackoffMs: 1 } };

async function fake(): Promise<FakeCasdoor> {
  const f = await startFakeCasdoor();
  fakes.push(f);
  return f;
}

function client(url: string, extra: Record<string, unknown> = {}): CasdoorClient {
  const c = new CasdoorClient({
    url,
    clientId: "cid",
    clientSecret: "csecret",
    organization: "acme",
    application: "app-acme",
    redirectUri: "https://app.test/cb",
    ...fast,
    ...extra,
  });
  clients.push(c);
  return c;
}

describe("CasdoorConfig", () => {
  it("uses defaults and freezes", () => {
    const c = new CasdoorConfig();
    expect(c.url).toBe("http://127.0.0.1:8000");
    expect(c.publicUrl).toBe(c.url);
    expect(c.scope).toBe("openid profile email");
    expect(c.adminUsername).toBe("admin");
    expect(c.adminOrganization).toBe("built-in");
    expect(c.adminApplication).toBe("app-built-in");
    expect(c.requireVerifiedEmail).toBe(true);
    expect(c.clientSecret).toBeUndefined();
    expect(Object.isFrozen(c)).toBe(true);
    expect(CasdoorConfig.from(c)).toBe(c);
    expect(CasdoorConfig.ENV_PREFIX).toBe("GROW_CASDOOR_");
  });

  it("reads the platform GROW_AUTH_* names with GROW_CASDOOR_* first", () => {
    const env = {
      GROW_AUTH_ISSUER: "http://casdoor:8000",
      GROW_AUTH_PUBLIC_URL: "https://auth.example.test/",
      GROW_AUTH_CLIENT_ID: "client-1",
      GROW_AUTH_CLIENT_SECRET: "secret-1",
      GROW_AUTH_ORG: "acme",
      GROW_AUTH_APP: "app-acme",
      GROW_AUTH_REDIRECT_URL: "https://app.test/cb",
      CASDOOR_ADMIN_PASSWORD: "adm1n-pass",
      GROW_CASDOOR_ORG: "override-org",
      GROW_CASDOOR_SCOPE: "openid",
      GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL: "false",
      GROW_CASDOOR_ADMIN_ORG: "built-in",
    };
    const c = CasdoorConfig.fromEnv({ application: "explicit" }, env);
    expect(c.url).toBe("http://casdoor:8000");
    expect(c.publicUrl).toBe("https://auth.example.test");
    expect(c.clientId).toBe("client-1");
    expect(c.clientSecret?.reveal()).toBe("secret-1");
    expect(c.organization).toBe("override-org");
    expect(c.application).toBe("explicit");
    expect(c.redirectUri).toBe("https://app.test/cb");
    expect(c.adminPassword?.reveal()).toBe("adm1n-pass");
    expect(c.scope).toBe("openid");
    expect(c.requireVerifiedEmail).toBe(false);
    expect(VENDOR_ENV.url?.[0]).toBe("GROW_AUTH_ISSUER");
  });

  it("falls back to the public URL when no issuer is set", () => {
    const c = CasdoorConfig.fromEnv({}, { GROW_AUTH_PUBLIC_URL: "https://auth.test" });
    expect(c.url).toBe("https://auth.test");
    expect(CasdoorConfig.fromEnv({}, {}).url).toBe(CasdoorConfig.DEFAULT_URL);
  });

  it("redacts credentials", () => {
    const c = new CasdoorConfig({
      clientSecret: new Secret("abcd-secret"),
      adminPassword: "pw-123456",
    });
    const text = `${c.toString()} ${inspect(c)} ${JSON.stringify(c)}`;
    expect(text).not.toContain("abcd-secret");
    expect(text).not.toContain("pw-123456");
    expect(text).toContain(REDACTED);
    expect(c.knownSecrets()).toEqual(["abcd-secret", "pw-123456"]);
    expect(new CasdoorConfig().toJSON().clientSecret).toBeNull();
  });

  it("validates", () => {
    expect(() => new CasdoorConfig({ clientSecret: " " })).toThrow(ConfigError);
    expect(() => new CasdoorConfig({ adminPassword: " " })).toThrow(ConfigError);
    expect(() => new CasdoorConfig({ publicUrl: "ftp://x" })).toThrow(ConfigError);
    expect(() => new CasdoorConfig({ url: "nope" })).toThrow(ConfigError);
  });
});

describe("CasdoorClient core", () => {
  it("health is ok on /api/health and unreachable on a closed port", async () => {
    const f = await fake();
    expect((await client(f.url).health()).healthy).toBe(true);
    const port = await closedPort();
    const h = await client(`http://127.0.0.1:${port}`).health();
    expect(h.healthy).toBe(false);
    expect(h.status).toBe("unreachable");
  });

  it("health reports a status error as unhealthy", async () => {
    const s = await startServer([{ body: { status: "error", msg: "db down" } }]);
    servers.push(s);
    expect((await client(s.url).health()).healthy).toBe(false);
  });

  it("ping uses the client credentials, or the admin session", async () => {
    const f = await fake();
    expect(await client(f.url).ping()).toBeGreaterThanOrEqual(0);
    await expect(client(f.url, { clientSecret: "wrong" }).ping()).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    expect(await client(f.url, { adminPassword: ADMIN_PASSWORD }).ping()).toBeGreaterThanOrEqual(0);
  });

  it("serverVersion needs the admin session", async () => {
    const f = await fake();
    expect(await client(f.url, { adminPassword: ADMIN_PASSWORD }).serverVersion()).toBe("v4.27.1");
    await expect(client(f.url).serverVersion()).rejects.toBeInstanceOf(PermissionDeniedError);
    const s = await startServer([{ body: { status: "ok", data: {} } }]);
    servers.push(s);
    await expect(client(s.url).serverVersion()).rejects.toBeInstanceOf(UnsupportedError);
  });

  it("a wrong admin password is an AuthenticationError, an empty one a ConfigError", async () => {
    const f = await fake();
    await expect(
      client(f.url, { adminPassword: "wrong-pass" }).serverVersion(),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it("re-signs the admin in once when the session expired", async () => {
    let logins = 0;
    let gets = 0;
    const s = await startServer((req) => {
      if (req.url.startsWith("/api/login")) {
        logins++;
        return {
          headers: { "set-cookie": `casdoor_session_id=s${logins}; Path=/` },
          body: { status: "ok" },
        };
      }
      gets++;
      return gets === 1
        ? { body: { status: "error", msg: "Please login first" } }
        : { body: { status: "ok", data: { version: "v1" } } };
    });
    servers.push(s);
    expect(await client(s.url, { adminPassword: "pw-123456" }).serverVersion()).toBe("v1");
    expect(logins).toBe(2);
  });

  it("fails when the admin sign-in sets no cookie", async () => {
    const s = await startServer([{ body: { status: "ok" } }]);
    servers.push(s);
    await expect(
      client(s.url, { adminPassword: "pw-123456" }).serverVersion(),
    ).rejects.toBeInstanceOf(ConfigError);
  });

  it("requires the client credentials for admin calls without an admin password", async () => {
    const f = await fake();
    await expect(client(f.url, { clientSecret: undefined }).ping()).rejects.toBeInstanceOf(
      ConfigError,
    );
    await expect(client(f.url, { clientId: undefined }).ping()).rejects.toBeInstanceOf(ConfigError);
  });

  it("rejects every call after close", async () => {
    const f = await fake();
    const c = client(f.url);
    await c.close();
    await c.close();
    await expect(c.signIn({ username: "a", password: "b" })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    expect(() => c.buildAuthorizeUrl({ redirectUri: "x", state: "s", codeChallenge: "c" })).toThrow(
      /closed/,
    );
  });

  it("fromEnv builds a client", () => {
    process.env.GROW_CASDOOR_URL = "http://casdoor.test:8000";
    try {
      const c = CasdoorClient.fromEnv({ organization: "o" });
      clients.push(c);
      expect(c.config.url).toBe("http://casdoor.test:8000");
      expect(c.transport.userAgent).toContain("grow-codes-casdoor");
    } finally {
      delete process.env.GROW_CASDOOR_URL;
    }
  });
});

describe("error normalization", () => {
  const cases: [string, new (...a: never[]) => CasdoorError, string][] = [
    ["Phone number is invalid in your region US", ValidationError, CasdoorReason.EmptyCredential],
    [
      "password or code is incorrect, you have 4 remaining chances",
      AuthenticationError,
      CasdoorReason.InvalidCredentials,
    ],
    ["Please login first", AuthenticationError, CasdoorReason.LoginRequired],
    ["Unauthorized operation", PermissionDeniedError, CasdoorReason.Forbidden],
    [
      "The user is forbidden to sign in, please contact the administrator",
      PermissionDeniedError,
      CasdoorReason.Forbidden,
    ],
    [
      "You have entered the wrong password or code too many times, please wait for 15 minutes and try again",
      RateLimitError,
      CasdoorReason.Locked,
    ],
    ["the account is frozen", PermissionDeniedError, CasdoorReason.Locked],
    ["you can only send one code in 60s", RateLimitError, CasdoorReason.RateLimited],
    [
      'pq: duplicate key value violates unique constraint "role_pkey"',
      ConflictError,
      CasdoorReason.AlreadyExists,
    ],
    ["The user: acme/x doesn't exist", NotFoundError, CasdoorReason.NotFound],
    [
      "The login method: login with email is not enabled",
      UnsupportedError,
      CasdoorReason.NotEnabled,
    ],
    ["something else", ValidationError, CasdoorReason.Other],
  ];
  it.each(cases)("maps %s", (msg, cls, reason) => {
    const err = envelopeError("op", msg, "c1");
    expect(err).toBeInstanceOf(cls);
    expect(casdoorReason(err)).toBe(reason);
    expect(err.message.startsWith("op: ")).toBe(true);
    expect((err as unknown as { casdoorCode?: string }).casdoorCode).toBe("c1");
  });

  it("explains the empty-credential message and sets retryAfter for rate limits", () => {
    expect(envelopeError("op", "Phone number is invalid in your region US").message).toContain(
      "empty password",
    );
    const rl = envelopeError("op", "you can only send one code in 60s");
    expect(rl.retryAfterMs).toBe(60_000);
    expect(rl.retryable).toBe(false);
    expect(envelopeError("op", "").message).toContain("status error");
    expect(envelopeError("op", "x".repeat(400)).message.length).toBeLessThan(320);
    expect(casdoorReason(new Error("x"))).toBeUndefined();
  });

  it("maps OAuth errors", () => {
    expect(oauthError("t", "invalid_grant", "bad code", 400)).toBeInstanceOf(AuthenticationError);
    expect(casdoorReason(oauthError("t", "invalid_grant", "the account is frozen", 400))).toBe(
      CasdoorReason.Locked,
    );
    expect(oauthError("t", "invalid_client", "", 400)).toBeInstanceOf(AuthenticationError);
    expect(oauthError("t", "unsupported_grant_type", "", 400)).toBeInstanceOf(UnsupportedError);
    expect(oauthError("t", "invalid_request", "", 400)).toBeInstanceOf(ValidationError);
    expect(casdoorReason(oauthError("t", "invalid_grant", "the user has MFA enabled", 400))).toBe(
      CasdoorReason.MfaRequired,
    );
    expect(maskedObjectError("op", "application")).toBeInstanceOf(PermissionDeniedError);
  });

  it("maps HTTP error responses with an envelope or an OAuth body", async () => {
    const s = await startServer((req) =>
      req.url.includes("oauth")
        ? { status: 500, body: { status: "error", msg: "Please login first" } }
        : { status: 403, body: { status: "error", msg: "Unauthorized operation" } },
    );
    servers.push(s);
    const c = client(s.url);
    await expect(c.ping()).rejects.toBeInstanceOf(PermissionDeniedError);
    await expect(c.refresh("rt")).rejects.toBeInstanceOf(AuthenticationError);
  });

  it("maps OAuth errors inside HTTP 200 bodies", async () => {
    const s = await startServer((req) =>
      req.url.includes("refresh")
        ? { body: { error: "invalid_grant", error_description: "expired" } }
        : { body: { status: "error", msg: "Please login first" } },
    );
    servers.push(s);
    const c = client(s.url);
    await expect(c.refresh("rt")).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      c.exchangeCode({ code: "c", codeVerifier: "v", redirectUri: "r" }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });
});

describe("helpers", () => {
  it("cookie jar keeps Set-Cookie values", () => {
    const jar = new CookieJar();
    expect(jar.header()).toBeUndefined();
    const h = new Headers();
    h.append("set-cookie", "a=1; Path=/");
    h.append("set-cookie", "b=2; HttpOnly");
    h.append("set-cookie", "broken");
    jar.absorb(h);
    expect(jar.header()).toBe("a=1; b=2");
    const legacy = { get: () => "c=3; Path=/, d=4", getSetCookie: undefined } as unknown as Headers;
    jar.absorb(legacy);
    expect(jar.header()).toContain("c=3");
    jar.clear();
    expect(jar.header()).toBeUndefined();
  });

  it("formBody skips undefined", () => {
    expect(formBody({ a: "1", b: undefined, c: "x y" })).toBe("a=1&c=x+y");
  });
});
