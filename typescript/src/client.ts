// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type HealthStatus,
  HttpTransport,
  type TransportOptions,
  UnsupportedError,
  healthStatus,
  probeHealth,
} from "./core/index.js";
import { CasdoorApi } from "./casdoor-api.js";
import { CasdoorConfig, type CasdoorConfigOptions } from "./config.js";
import * as admin from "./admin-ops.js";
import * as flows from "./user-flows.js";
import type {
  ApplicationInfo,
  AuthorizeUrlInput,
  CasdoorUser,
  EnsureApplicationInput,
  EnsureOrganizationInput,
  EnsureUserInput,
  ExchangeCodeInput,
  ResetPasswordInput,
  RoleInfo,
  SignInInput,
  SignUpInput,
  SignUpResult,
  SmtpSettings,
  TokenSet,
  TotpSetup,
  VerifyEmailInput,
  VerifyTotpInput,
} from "./types.js";

/** Per-call options. */
export interface CallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Options of {@link CasdoorClient.sendEmailVerification}. */
export interface SendEmailVerificationOptions extends CallOptions {
  /**
   * `signup`: code for a new address (pass it to `signUp({emailCode})`); `verify`: code for an
   * existing user (then `verifyEmail`); `auto` (default): `verify`, falling back to `signup`.
   */
  purpose?: "auto" | "signup" | "verify";
}

/** Options of the admin calls that take an organization. */
export interface OrganizationOptions extends CallOptions {
  /** Organization (default: config `organization`). */
  organization?: string;
}

/** Test seams (undici `MockAgent`, fake sleep). Not part of the stable API. */
export type ClientInternals = Pick<TransportOptions, "dispatcher" | "sleep" | "now">;

/**
 * Client for Casdoor: user flows for backends-for-frontends and idempotent admin operations.
 *
 * Every Casdoor `{"status":"error"}` answer (HTTP 200) and every OAuth error becomes a typed
 * {@link CasdoorError} subclass with a `casdoorReason`.
 */
export class CasdoorClient {
  /** The immutable configuration. */
  readonly config: CasdoorConfig;
  readonly #transport: HttpTransport;
  readonly #api: CasdoorApi;
  #closed = false;

  /** Accepts a {@link CasdoorConfig} or plain options. */
  constructor(config: CasdoorConfigOptions = {}, internals: ClientInternals = {}) {
    const cfg = CasdoorConfig.from(config);
    this.config = cfg;
    this.#transport = new HttpTransport({
      ...internals,
      config: cfg,
      knownSecrets: () => cfg.knownSecrets(),
    });
    this.#api = new CasdoorApi(cfg, this.#transport);
  }

  /**
   * Builds a client from the environment: `GROW_CASDOOR_*`, then the platform names
   * `GROW_AUTH_ISSUER|PUBLIC_URL`, `GROW_AUTH_CLIENT_ID/SECRET`, `GROW_AUTH_ORG/APP`,
   * `GROW_AUTH_REDIRECT_URL`, `CASDOOR_ADMIN_PASSWORD`.
   */
  static fromEnv(overrides: CasdoorConfigOptions = {}): CasdoorClient {
    return new CasdoorClient(CasdoorConfig.fromEnv(overrides));
  }

  /** The shared HTTP transport (for service modules). @internal */
  get transport(): HttpTransport {
    return this.#transport;
  }

  /** Unauthenticated liveness: `GET /api/health`. Never throws for an unhealthy service. */
  health(options: CallOptions = {}): Promise<HealthStatus> {
    return probeHealth(async () => {
      const res = await this.#transport.get<{ status?: unknown; msg?: unknown } | undefined>(
        "/api/health",
        { operation: "health", ...options },
      );
      const status = res.data?.status;
      return healthStatus(
        status === "ok" ? "ok" : typeof status === "string" ? status : "unhealthy",
        {},
      );
    });
  }

  /**
   * Authenticated round trip with the admin credentials (admin session or client credentials):
   * reads the application. Returns the latency in milliseconds.
   */
  async ping(options: CallOptions = {}): Promise<number> {
    const start = performance.now();
    const app = this.config.application ?? this.config.adminApplication;
    await this.#api.call({
      operation: "ping",
      path: "/api/get-application",
      query: { id: `admin/${app}` },
      auth: "admin",
      ...options,
    });
    return performance.now() - start;
  }

  /** Server version (`/api/get-version-info`, needs the admin session). */
  async serverVersion(options: CallOptions = {}): Promise<string> {
    const env = await this.#api.call<{ version?: unknown }>({
      operation: "serverVersion",
      path: "/api/get-version-info",
      auth: "admin",
      ...options,
    });
    const version = env.data?.version;
    if (typeof version !== "string" || version === "") {
      throw new UnsupportedError("serverVersion: the service does not report a version");
    }
    return version;
  }

  // ---------------------------------------------------------------- user flows

  /** Registers a user (`/api/signup`). Pass `emailCode` when the application requires it. */
  signUp(input: SignUpInput, options: CallOptions = {}): Promise<SignUpResult> {
    return flows.signUp(this.#api, input, options.signal);
  }

  /**
   * Headless password sign-in (code flow + PKCE inside the BFF). Throws `MfaRequiredError` when
   * the user has TOTP and no `totpCode`/`recoveryCode` was given, `EmailNotVerifiedError` when the
   * e-mail is not verified and `requireVerifiedEmail` is on.
   */
  signIn(input: SignInInput, options: CallOptions = {}): Promise<TokenSet> {
    return flows.signIn(this.#api, input, options.signal);
  }

  /** New tokens from a refresh token. */
  refresh(refreshToken: string, options: CallOptions = {}): Promise<TokenSet> {
    return flows.refresh(this.#api, refreshToken, options.signal);
  }

  /** Ends the Casdoor session of the token (access or id token). Idempotent. */
  signOut(token: string, options: CallOptions = {}): Promise<void> {
    return flows.signOut(this.#api, token, options.signal);
  }

  /** Mails a verification code (Casdoor allows one code per address per 60 s → `RateLimitError`). */
  sendEmailVerification(email: string, options: SendEmailVerificationOptions = {}): Promise<void> {
    return flows.sendEmailVerification(this.#api, email, options.purpose ?? "auto", options.signal);
  }

  /** Checks the code and marks the user's e-mail verified (needs the client credentials). */
  verifyEmail(input: VerifyEmailInput, options: CallOptions = {}): Promise<void> {
    return flows.verifyEmail(this.#api, input, options.signal);
  }

  /** Mails a password reset code. Throws `NotFoundError` for unknown e-mails (do not reveal it). */
  forgotPassword(email: string, options: CallOptions = {}): Promise<void> {
    return flows.forgotPassword(this.#api, email, options.signal);
  }

  /** Sets a new password with the code from {@link forgotPassword}. */
  resetPassword(input: ResetPasswordInput, options: CallOptions = {}): Promise<void> {
    return flows.resetPassword(this.#api, input, options.signal);
  }

  /** Browser authorize URL on `publicUrl` (code flow, PKCE S256). */
  buildAuthorizeUrl(input: AuthorizeUrlInput): string {
    this.#transport.ensureOpen("buildAuthorizeUrl");
    return flows.buildAuthorizeUrl(this.#api, input);
  }

  /** Exchanges the authorization code from the browser redirect for tokens. */
  exchangeCode(input: ExchangeCodeInput, options: CallOptions = {}): Promise<TokenSet> {
    return flows.exchangeCode(this.#api, input, options.signal);
  }

  /** Starts TOTP enrollment for the user of the access token. */
  setupTotp(accessToken: string, options: CallOptions = {}): Promise<TotpSetup> {
    return flows.setupTotp(this.#api, accessToken, options.signal);
  }

  /** Verifies the first TOTP code and enables TOTP for the user. */
  verifyTotp(input: VerifyTotpInput, options: CallOptions = {}): Promise<void> {
    return flows.verifyTotp(this.#api, input, options.signal);
  }

  // ---------------------------------------------------------------- admin

  /** Creates the organization unless it exists (password rules, TOTP offered). */
  ensureOrganization(
    input: EnsureOrganizationInput,
    options: CallOptions = {},
  ): Promise<{ name: string; created: boolean }> {
    return admin.ensureOrganization(this.#api, input, options.signal);
  }

  /** Creates or aligns the OAuth application; returns its client credentials. */
  ensureApplication(
    input: EnsureApplicationInput = {},
    options: CallOptions = {},
  ): Promise<ApplicationInfo> {
    return admin.ensureApplication(this.#api, input, options.signal);
  }

  /** Creates or aligns an SMTP e-mail provider and lists it on the configured application. */
  ensureEmailProvider(
    smtp: SmtpSettings,
    options: CallOptions = {},
  ): Promise<{ name: string; created: boolean }> {
    return admin.ensureEmailProvider(this.#api, smtp, options.signal);
  }

  /** Creates every missing role. */
  ensureRoles(names: readonly string[], options: OrganizationOptions = {}): Promise<RoleInfo[]> {
    return admin.ensureRoles(this.#api, names, options.organization, options.signal);
  }

  /** Creates or aligns a user (verified e-mail by default) and assigns its roles. */
  ensureUser(input: EnsureUserInput, options: CallOptions = {}): Promise<CasdoorUser> {
    return admin.ensureUser(this.#api, input, options.signal);
  }

  /** Adds a user (`org/name`, name or e-mail) to roles, creating missing roles. */
  assignRoles(
    user: string,
    roles: readonly string[],
    options: OrganizationOptions = {},
  ): Promise<void> {
    return admin.assignRoles(this.#api, user, roles, options.organization, options.signal);
  }

  /** Releases connections. Idempotent. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#transport.close();
  }
}
