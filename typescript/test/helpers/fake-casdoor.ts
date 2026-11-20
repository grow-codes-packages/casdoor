// Service-owned: a stateful fake Casdoor for unit tests. It reproduces the quirks the client
// must handle: HTTP 200 + {"status":"error"}, "Phone number is invalid" for an empty password,
// masked "***" secrets for non-admins, full-object updates, cookie sessions, PKCE, NextMfa,
// one verification code per address per 60 s.

import { createHash } from "node:crypto";
import { totpCode } from "../../src/pkce.js";
import { type MockServer, type RecordedRequest, type MockResponse, startServer } from "./server.js";

type Obj = Record<string, unknown>;

export const ADMIN_PASSWORD = "admin-pass-123";

/** State and controls of the fake. */
export interface FakeCasdoor {
  url: string;
  server: MockServer;
  orgs: Map<string, Obj>;
  apps: Map<string, Obj>;
  providers: Map<string, Obj>;
  roles: Map<string, Obj>;
  users: Map<string, Obj>;
  /** Last code mailed per address. */
  mails: Map<string, string>;
  /** Paths called, in order. */
  calls: string[];
  close(): Promise<void>;
}

const ok = (data: unknown = null, data2: unknown = null): MockResponse => ({
  body: { status: "ok", msg: "", data, data2 },
});
const fail = (msg: string, code?: string): MockResponse => ({
  body: { status: "error", msg, ...(code === undefined ? {} : { code }), data: null },
});

function b64(obj: Obj): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

/** Starts the fake with one organization `acme`, application `app-acme` (client `cid`/`csecret`). */
export async function startFakeCasdoor(): Promise<FakeCasdoor> {
  const orgs = new Map<string, Obj>([["admin/acme", { owner: "admin", name: "acme", mfaItems: [] }]]);
  const apps = new Map<string, Obj>([
    [
      "admin/app-acme",
      {
        owner: "admin",
        name: "app-acme",
        organization: "acme",
        clientId: "cid",
        clientSecret: "csecret",
        cert: "cert-built-in",
        redirectUris: ["https://app.test/cb"],
        providers: [],
        tokenFormat: "JWT",
      },
    ],
  ]);
  const providers = new Map<string, Obj>();
  const roles = new Map<string, Obj>();
  const users = new Map<string, Obj>();
  const mails = new Map<string, string>();
  const mailTimes = new Map<string, number>();
  const sessions = new Map<string, Obj>();
  const accessTokens = new Map<string, string>();
  const refreshTokens = new Map<string, string>();
  const authCodes = new Map<string, Obj>();
  const calls: string[] = [];
  let seq = 0;

  const next = (p: string): string => `${p}${++seq}`;

  function issue(userId: string): Obj {
    const u = users.get(userId) ?? {};
    const userRoles = [...roles.values()]
      .filter((r) => (r.users as string[]).includes(userId))
      .map((r) => ({ name: r.name }));
    const payload = {
      owner: u.owner,
      name: u.name,
      email: u.email,
      email_verified: u.emailVerified === true,
      roles: userRoles,
      iss: "http://casdoor:8000",
      aud: "cid",
    };
    const access = `${b64({ alg: "RS256" })}.${b64(payload)}.${next("sig")}`;
    const refresh = next("rt");
    accessTokens.set(access, userId);
    refreshTokens.set(refresh, userId);
    return { access_token: access, refresh_token: refresh, id_token: access, token_type: "Bearer", expires_in: 3600, scope: "openid" };
  }

  function session(req: RecordedRequest): { id: string; data: Obj; fresh: boolean } {
    const cookie = req.headers.cookie ?? "";
    const id = /casdoor_session_id=([^;]+)/.exec(cookie)?.[1];
    if (id !== undefined && sessions.has(id)) return { id, data: sessions.get(id) ?? {}, fresh: false };
    const nid = next("sess");
    sessions.set(nid, {});
    return { id: nid, data: sessions.get(nid) ?? {}, fresh: true };
  }

  /** "admin" (global admin), "app" (client credentials), a user id (bearer) or undefined. */
  function who(req: RecordedRequest, sess: Obj): string | undefined {
    const auth = req.headers.authorization ?? "";
    if (auth.startsWith("Basic ")) {
      const [id, secret] = Buffer.from(auth.slice(6), "base64").toString().split(":");
      const app = [...apps.values()].find((a) => a.clientId === id && a.clientSecret === secret);
      return app === undefined ? "bad" : "app";
    }
    if (auth.startsWith("Bearer ")) return accessTokens.get(auth.slice(7)) ?? "expired";
    return typeof sess.user === "string" ? sess.user : undefined;
  }

  const isAdmin = (w: string | undefined): boolean => w === "admin" || w === "app";

  function form(req: RecordedRequest): Record<string, string> {
    return Object.fromEntries(new URLSearchParams(req.body));
  }

  function json(req: RecordedRequest): Obj {
    return req.body === "" ? {} : (JSON.parse(req.body) as Obj);
  }

  function findUser(owner: string, nameOrEmail: string): Obj | undefined {
    return [...users.values()].find(
      (u) => u.owner === owner && (u.name === nameOrEmail || u.email === nameOrEmail),
    );
  }

  function mask(obj: Obj, keys: string[]): Obj {
    const out = { ...obj };
    for (const k of keys) if (k in out) out[k] = "***";
    return out;
  }

  const store: Record<string, Map<string, Obj>> = {
    organization: orgs,
    application: apps,
    provider: providers,
    role: roles,
    user: users,
  };

  function handle(req: RecordedRequest): MockResponse {
    const url = new URL(req.url, "http://fake");
    const path = url.pathname;
    calls.push(path);
    const q = url.searchParams;
    const sess = session(req);
    const res = route(req, path, q, sess.data);
    if (sess.fresh) res.headers = { ...res.headers, "set-cookie": `casdoor_session_id=${sess.id}; Path=/; HttpOnly` };
    return res;
  }

  function route(req: RecordedRequest, path: string, q: URLSearchParams, sess: Obj): MockResponse {
    const w = who(req, sess);
    if (w === "bad") return fail("Please login first");
    if (w === "expired") return { status: 401, body: { status: "error", msg: "Access token has expired" } };
    if (path === "/api/health") return ok();
    if (path === "/api/get-version-info") return w === "admin" ? ok({ version: "v4.27.1" }) : fail("Unauthorized operation");

    if (path === "/api/login") {
      const body = json(req);
      const issueCode = (user: Obj): MockResponse => {
        const code = next("code");
        authCodes.set(code, {
          user: `${String(user.owner)}/${String(user.name)}`,
          challenge: q.get("code_challenge"),
          redirect: q.get("redirectUri"),
        });
        return ok(code);
      };
      if (body.password === undefined && typeof sess.mfaUser === "string") {
        const user = users.get(sess.mfaUser) ?? {};
        const secret = typeof user.totpSecret === "string" ? user.totpSecret : "";
        const passOk = body.passcode !== undefined && body.passcode === totpCode(secret);
        const recOk = body.recoveryCode !== undefined && body.recoveryCode === user.recoveryCode;
        if (!passOk && !recOk)
          return fail("totp passcode error, password or code is incorrect, you have 4 remaining chances", "mfa-failed");
        delete sess.mfaUser;
        return issueCode(user);
      }
      if (body.password === "" || body.password === undefined) return fail("Phone number is invalid in your region US");
      if (q.get("clientId") === null) {
        if (body.organization === "built-in" && body.username === "admin" && body.password === ADMIN_PASSWORD) {
          sess.user = "admin";
          return ok("built-in/admin");
        }
        return fail("password or code is incorrect, you have 4 remaining chances", "wrong-password");
      }
      const user = findUser(String(body.organization), String(body.username));
      if (user === undefined) return fail("The user: acme/" + String(body.username) + " doesn't exist");
      if (user.isForbidden === true) return fail("The user is forbidden to sign in, please contact the administrator");
      if (user.password !== body.password) return fail("password or code is incorrect, you have 4 remaining chances", "wrong-password");
      if (typeof user.totpSecret === "string" && user.totpSecret !== "") {
        // Like Casdoor: a passcode in the password step is ignored.
        sess.mfaUser = `${String(user.owner)}/${String(user.name)}`;
        return ok("NextMfa", [{ enabled: true, mfaType: "app" }]);
      }
      return issueCode(user);
    }

    if (path === "/api/login/oauth/access_token") {
      const f = form(req);
      const app = [...apps.values()].find((a) => a.clientId === f.client_id);
      if (app === undefined || app.clientSecret !== f.client_secret) return { status: 400, body: { error: "invalid_client", error_description: "client_secret is invalid" } };
      const entry = authCodes.get(f.code ?? "");
      if (entry === undefined) return { status: 400, body: { error: "invalid_grant", error_description: "authorization code is invalid" } };
      authCodes.delete(f.code ?? "");
      const challenge = createHash("sha256").update(f.code_verifier ?? "").digest("base64url");
      if (challenge !== entry.challenge) return { status: 400, body: { error: "invalid_grant", error_description: "code_verifier is invalid" } };
      return { body: issue(String(entry.user)) };
    }

    if (path === "/api/login/oauth/refresh_token") {
      const f = form(req);
      const userId = refreshTokens.get(f.refresh_token ?? "");
      if (userId === undefined) return { status: 400, body: { error: "invalid_grant", error_description: "refresh token is invalid or revoked" } };
      refreshTokens.delete(f.refresh_token ?? "");
      return { body: issue(userId) };
    }

    if (path === "/api/logout") {
      const token = q.get("id_token_hint") ?? "";
      if (!accessTokens.has(token)) return { status: 401, body: { status: "error", msg: "Access token has expired" } };
      accessTokens.delete(token);
      return ok();
    }

    if (path === "/api/signup") {
      const body = json(req);
      if (body.password === "") return fail("Phone number is invalid in your region US");
      const app = apps.get(`admin/${String(body.application)}`);
      const needsCode = ((app?.signupItems as Obj[] | undefined) ?? []).some((i) => i.name === "Email" && i.rule === "Normal");
      if (findUser(String(body.organization), String(body.username)) !== undefined) return fail("The username already exists");
      if (needsCode && body.emailCode !== mails.get(String(body.email))) return fail("password or code is incorrect, you have 4 remaining chances");
      const id = `${String(body.organization)}/${String(body.username)}`;
      users.set(id, {
        owner: body.organization,
        name: body.username,
        email: body.email,
        password: body.password,
        displayName: body.displayName,
        emailVerified: needsCode,
        isForbidden: false,
      });
      return ok(id);
    }

    if (path === "/api/send-verification-code") {
      const f = form(req);
      const dest = f.dest ?? "";
      const last = mailTimes.get(dest);
      if (last !== undefined && Date.now() - last < 60_000) return fail("you can only send one code in 60s");
      const org = apps.get(f.applicationId ?? "")?.organization;
      const owner = typeof org === "string" ? org : "";
      const user = findUser(owner, dest);
      if ((f.method === "login" || f.method === "forget") && user === undefined) return fail("the user does not exist, please sign up first");
      if (f.method === "signup" && user !== undefined) return fail("Email already exists");
      if (f.method === "forget" && findUser(owner, f.checkUser ?? "") === undefined) return fail("the user does not exist, please sign up first");
      const code = String(100000 + seq++);
      mails.set(dest, code);
      mailTimes.set(dest, Date.now());
      return ok();
    }

    if (path === "/api/verify-code") {
      const body = json(req);
      if (body.code === "" || body.code === undefined) return fail("Phone number is invalid in your region US");
      if (mails.get(String(body.username)) !== body.code) return fail("password or code is incorrect, you have 4 remaining chances");
      sess.verifiedCode = body.code;
      return ok();
    }

    if (path === "/api/set-password") {
      const f = form(req);
      if (f.code === undefined || sess.verifiedCode !== f.code) return fail("Please login first");
      const user = users.get(`${f.userOwner ?? ""}/${f.userName ?? ""}`);
      if (user === undefined) return fail("The user doesn't exist");
      user.password = f.newPassword;
      return ok();
    }

    if (path.startsWith("/api/mfa/setup/")) {
      const f = form(req);
      const userId = `${f.owner ?? ""}/${f.name ?? ""}`;
      if (w !== userId) return fail("Unauthorized operation");
      const user = users.get(userId);
      if (user === undefined) return fail("User doesn't exist");
      const org = orgs.get(`admin/${String(user.owner)}`);
      const allowed = ((org?.mfaItems as Obj[] | undefined) ?? []).some((i) => i.name === "app");
      if (!allowed) return fail("the MFA type: app is not allowed by the MFA items");
      if (path.endsWith("/initiate")) return ok({ secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", url: "otpauth://totp/x", recoveryCodes: ["rc-1"] });
      if (path.endsWith("/verify")) {
        if (f.secret === undefined || f.secret === "") return fail("totp secret is missing");
        return f.passcode === totpCode(f.secret) ? ok("OK") : fail("passcode is invalid");
      }
      if (f.secret === undefined || f.secret === "") return fail("totp secret is missing");
      user.totpSecret = f.secret;
      user.recoveryCode = f.recoveryCodes;
      return ok("OK");
    }

    const m = /^\/api\/(get|add|update)-(organization|application|provider|role|user)$/.exec(path);
    if (m !== null) {
      const [, verb, kind] = m as unknown as [string, string, string];
      const map = store[kind] as Map<string, Obj>;
      if (verb === "get") {
        if (kind === "application" || kind === "organization") {
          const obj = map.get(q.get("id") ?? "");
          if (obj === undefined) return ok(null);
          return ok(isAdmin(w) ? obj : mask(obj, ["clientSecret", "cert"]));
        }
        if (!isAdmin(w)) return fail("Please login first");
        if (kind === "user" && q.get("email") !== null) {
          const u = findUser(q.get("owner") ?? "", q.get("email") ?? "");
          return ok(u === undefined ? null : mask(u, ["password"]));
        }
        const obj = map.get(q.get("id") ?? "");
        return ok(obj === undefined ? null : kind === "user" ? mask(obj, ["password"]) : obj);
      }
      if (!isAdmin(w)) return fail("Please login first");
      const body = json(req);
      if (verb === "add") {
        const id = `${String(body.owner)}/${String(body.name)}`;
        if (map.has(id)) return fail('pq: duplicate key value violates unique constraint "pkey"');
        if (kind === "user" && body.password === "") return fail("Phone number is invalid in your region US");
        map.set(id, { ...body });
        return ok("Affected");
      }
      const id = q.get("id") ?? "";
      const cur = map.get(id);
      if (cur === undefined) return fail(`The ${kind}: ${id} does not exist`);
      // Full-object update: missing fields are reset (the quirk the client must respect).
      const nextObj: Obj = { ...body };
      if (kind === "user" && body.password === "***") nextObj.password = cur.password;
      if (body.clientSecret === "***") nextObj.clientSecret = "***";
      map.set(id, nextObj);
      return ok("Affected");
    }
    return { status: 404, body: "not found" };
  }

  const server = await startServer((req) => handle(req));
  return {
    url: server.url,
    server,
    orgs,
    apps,
    providers,
    roles,
    users,
    mails,
    calls,
    close: () => server.close(),
  };
}
