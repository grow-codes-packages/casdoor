// Service-owned: Casdoor HTTP calls on top of the core transport.
//
// - Envelope calls (`/api/*`): HTTP 200 + `{"status":"error"}` → typed error (casdoor-errors.ts).
// - OAuth calls (`/api/login/oauth/*`): form bodies, `{"error":…}` bodies → typed error.
// - Cookie jars for the flows that need a Casdoor session across calls (verify-code →
//   set-password, admin session, MFA sign-in).

import {
  CasdoorError,
  ConfigError,
  type ErrorResponse,
  type HttpTransport,
  type QueryValue,
} from "./core/index.js";
import { CasdoorReason, envelopeError, oauthError } from "./casdoor-errors.js";
import type { CasdoorConfig } from "./config.js";

/** The Casdoor response envelope. */
export interface Envelope<T = unknown> {
  status?: string;
  msg?: string;
  code?: string;
  data?: T;
  data2?: unknown;
}

/** Minimal cookie jar (one Casdoor origin). */
export class CookieJar {
  readonly #cookies = new Map<string, string>();

  /** `Cookie` header value, or `undefined` when empty. */
  header(): string | undefined {
    if (this.#cookies.size === 0) return undefined;
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  /** Stores the `Set-Cookie` values of a response. */
  absorb(headers: Headers): void {
    const list =
      typeof headers.getSetCookie === "function"
        ? headers.getSetCookie()
        : (headers.get("set-cookie") ?? "").split(/,(?=[^;]+=)/);
    for (const raw of list) {
      const pair = raw.split(";")[0] ?? "";
      const eq = pair.indexOf("=");
      if (eq <= 0) continue;
      this.#cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  /** Forgets every cookie. */
  clear(): void {
    this.#cookies.clear();
  }
}

/** Who authenticates a call. */
export type CallAuth = "none" | "admin" | "client";

/** One envelope call. */
export interface ApiCall {
  operation: string;
  method?: "GET" | "POST";
  path: string;
  query?: Readonly<Record<string, QueryValue>>;
  json?: unknown;
  form?: Readonly<Record<string, string | undefined>>;
  auth?: CallAuth;
  /** User access token sent as `Authorization: Bearer`. */
  bearer?: string;
  jar?: CookieJar;
  signal?: AbortSignal;
}

/** Form-encodes a record, skipping `undefined`. */
export function formBody(form: Readonly<Record<string, string | undefined>>): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(form)) if (v !== undefined) params.append(k, v);
  return params.toString();
}

/** Casdoor API access shared by the client modules. */
export class CasdoorApi {
  readonly config: CasdoorConfig;
  readonly transport: HttpTransport;
  readonly #adminJar = new CookieJar();
  #adminSignedIn = false;

  constructor(config: CasdoorConfig, transport: HttpTransport) {
    this.config = config;
    this.transport = transport;
  }

  /** Organization from the config or a {@link ConfigError}. */
  organization(operation: string, override?: string): string {
    const org = override ?? this.config.organization;
    if (org === undefined) throw new ConfigError(`${operation}: organization is not configured`);
    return org;
  }

  /** Application from the config or a {@link ConfigError}. */
  application(operation: string, override?: string): string {
    const app = override ?? this.config.application;
    if (app === undefined) throw new ConfigError(`${operation}: application is not configured`);
    return app;
  }

  /** Client id from the config or a {@link ConfigError}. */
  clientId(operation: string): string {
    const id = this.config.clientId;
    if (id === undefined) throw new ConfigError(`${operation}: clientId is not configured`);
    return id;
  }

  /** Client secret from the config or a {@link ConfigError}. */
  clientSecret(operation: string): string {
    const secret = this.config.clientSecret?.reveal();
    if (secret === undefined) throw new ConfigError(`${operation}: clientSecret is not configured`);
    return secret;
  }

  /**
   * Sends an envelope call and returns the `status: ok` envelope.
   *
   * @throws {CasdoorError} The normalized error for `status: error`.
   */
  async call<T = unknown>(call: ApiCall): Promise<Envelope<T>> {
    if (call.auth === "admin" && this.config.adminPassword !== undefined) {
      const viaSession: ApiCall = { ...call, auth: "none", jar: this.#adminJar };
      await this.#ensureAdminSession(call.operation, call.signal);
      try {
        return await this.#send<T>(viaSession);
      } catch (err) {
        if (!isLoginRequired(err)) throw err;
        this.#adminSignedIn = false;
        await this.#ensureAdminSession(call.operation, call.signal);
        return this.#send<T>(viaSession);
      }
    }
    return this.#send<T>(call);
  }

  async #send<T>(call: ApiCall): Promise<Envelope<T>> {
    const headers: Record<string, string> = {};
    if (call.auth === "admin" || call.auth === "client") {
      const id = this.clientId(call.operation);
      const secret = this.clientSecret(call.operation);
      headers.authorization = `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
    }
    if (call.bearer !== undefined) headers.authorization = `Bearer ${call.bearer}`;
    const cookie = call.jar?.header();
    if (cookie !== undefined) headers.cookie = cookie;
    let body: string | undefined;
    if (call.form !== undefined) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      body = formBody(call.form);
    }
    const res = await this.transport.request<Envelope<T> | undefined>({
      method: call.method ?? (call.json !== undefined || call.form !== undefined ? "POST" : "GET"),
      path: call.path,
      operation: call.operation,
      headers,
      ...(call.query === undefined ? {} : { query: call.query }),
      ...(call.json === undefined ? {} : { json: call.json }),
      ...(body === undefined ? {} : { body }),
      ...(call.signal === undefined ? {} : { signal: call.signal }),
      classifyError: (r) => this.#classifyEnvelope(r),
    });
    call.jar?.absorb(res.headers);
    const envelope = res.data ?? {};
    if (envelope.status === "error") {
      throw envelopeError(
        call.operation,
        this.transport.redact(text(envelope.msg)),
        envelope.code,
        res.status,
      );
    }
    return envelope;
  }

  /** Casdoor also answers some errors with 401/403 + an envelope (expired access tokens). */
  #classifyEnvelope(r: ErrorResponse): CasdoorError | undefined {
    const parsed = parseJson(r.body);
    if (parsed?.status === "error" && typeof parsed.msg === "string") {
      return envelopeError(r.operation, this.transport.redact(parsed.msg), undefined, r.status);
    }
    return undefined;
  }

  /**
   * Posts a form to an OAuth endpoint and returns its JSON body.
   *
   * @throws {CasdoorError} Normalized OAuth errors.
   */
  async oauth(
    operation: string,
    path: string,
    form: Readonly<Record<string, string | undefined>>,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> {
    const res = await this.transport.request<Record<string, unknown> | undefined>({
      method: "POST",
      path,
      operation,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: formBody(form),
      ...(signal === undefined ? {} : { signal }),
      classifyError: (r) => {
        const parsed = parseJson(r.body);
        if (typeof parsed?.error === "string") {
          return oauthError(
            r.operation,
            parsed.error,
            this.transport.redact(text(parsed.error_description)),
            r.status,
          );
        }
        return this.#classifyEnvelope(r);
      },
    });
    const data = res.data ?? {};
    if (typeof data.error === "string" && data.error !== "") {
      throw oauthError(
        operation,
        data.error,
        this.transport.redact(text(data.error_description)),
        res.status,
      );
    }
    if (data.status === "error") {
      throw envelopeError(operation, this.transport.redact(text(data.msg)), undefined);
    }
    return data;
  }

  /** Signs the built-in admin in once (cookie session). */
  async #ensureAdminSession(operation: string, signal?: AbortSignal): Promise<void> {
    if (this.#adminSignedIn) return;
    const password = this.config.adminPassword?.reveal() ?? "";
    if (password === "") {
      throw new ConfigError(
        `${operation}: adminPassword is empty (Casdoor would answer "Phone number is invalid")`,
      );
    }
    this.#adminJar.clear();
    await this.#send({
      operation: `${operation} (admin sign-in)`,
      method: "POST",
      path: "/api/login",
      json: {
        application: this.config.adminApplication,
        organization: this.config.adminOrganization,
        username: this.config.adminUsername,
        password,
        type: "login",
        signinMethod: "Password",
        autoSignin: false,
      },
      jar: this.#adminJar,
      ...(signal === undefined ? {} : { signal }),
    });
    if (this.#adminJar.header() === undefined) {
      throw new ConfigError(
        `${operation}: Casdoor returned no session cookie for the admin sign-in`,
      );
    }
    this.#adminSignedIn = true;
  }
}

/** True for "Please login first"-style errors. */
function isLoginRequired(err: unknown): boolean {
  return (
    err instanceof CasdoorError &&
    (err as { casdoorReason?: string }).casdoorReason === CasdoorReason.LoginRequired
  );
}

/** A string value or `""`. */
function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** Parses a JSON object or returns `undefined`. */
function parseJson(text: string): Record<string, unknown> | undefined {
  try {
    const v: unknown = JSON.parse(text);
    return v !== null && typeof v === "object" ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}
