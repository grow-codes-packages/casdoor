// Service-owned: generated once by sdk-kit, then maintained in this repository.

import {
  type CommonConfig,
  type CommonConfigOptions,
  type CommonVendorEnv,
  ConfigError,
  type EnvMap,
  EnvReader,
  type Hooks,
  type ClientLogger,
  REDACTED,
  type RetryPolicy,
  Secret,
  type TlsOptions,
  describeCommonConfig,
  mergeOptions,
  readCommonEnv,
  resolveCommonConfig,
  secretValues,
  validateCommonConfig,
} from "./core/index.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** Port text from the stack catalog; the default URL uses its first number. */
const CATALOG_PORT = "8000";

/** Default OAuth scopes requested by sign-in and the authorize URL. */
export const DEFAULT_SCOPE = "openid profile email";

/** Options accepted by {@link CasdoorConfig} (all optional). */
export interface CasdoorConfigOptions extends CommonConfigOptions {
  /**
   * Browser-facing Casdoor URL used by {@link CasdoorClient.buildAuthorizeUrl}
   * (env `GROW_CASDOOR_PUBLIC_URL`, `GROW_AUTH_PUBLIC_URL`). Defaults to `url`.
   */
  publicUrl?: string;
  /** OAuth client id of the application (env `GROW_CASDOOR_CLIENT_ID`, `GROW_AUTH_CLIENT_ID`). */
  clientId?: string;
  /** OAuth client secret (env `GROW_CASDOOR_CLIENT_SECRET`, `GROW_AUTH_CLIENT_SECRET`). */
  clientSecret?: string | Secret;
  /** Casdoor organization (env `GROW_CASDOOR_ORG`, `GROW_AUTH_ORG`). */
  organization?: string;
  /** Casdoor application name (env `GROW_CASDOOR_APP`, `GROW_AUTH_APP`). */
  application?: string;
  /** Default redirect URI of the code flow (env `GROW_CASDOOR_REDIRECT_URL`, `GROW_AUTH_REDIRECT_URL`). */
  redirectUri?: string;
  /** OAuth scopes (env `GROW_CASDOOR_SCOPE`; default `openid profile email`). */
  scope?: string;
  /**
   * Built-in admin user for admin operations (env `GROW_CASDOOR_ADMIN_USERNAME`,
   * `CASDOOR_ADMIN_USERNAME`; default `admin`).
   */
  adminUsername?: string;
  /**
   * Built-in admin password (env `GROW_CASDOOR_ADMIN_PASSWORD`, `CASDOOR_ADMIN_PASSWORD`). When
   * unset, admin operations authenticate with the client id/secret (HTTP Basic).
   */
  adminPassword?: string | Secret;
  /** Organization of the admin user (env `GROW_CASDOOR_ADMIN_ORG`; default `built-in`). */
  adminOrganization?: string;
  /** Application of the admin user (env `GROW_CASDOOR_ADMIN_APP`; default `app-built-in`). */
  adminApplication?: string;
  /**
   * Refuse tokens of users whose e-mail is not verified (`EmailNotVerifiedError`)
   * (env `GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL`; default `true`).
   */
  requireVerifiedEmail?: boolean;
}

/**
 * Vendor environment variables read after `GROW_CASDOOR_*`, in order. The platform names
 * (`GROW_AUTH_*`, `CASDOOR_ADMIN_*`) come first.
 */
export const VENDOR_ENV: CommonVendorEnv & {
  publicUrl: readonly string[];
  clientId: readonly string[];
  clientSecret: readonly string[];
  organization: readonly string[];
  application: readonly string[];
  redirectUri: readonly string[];
  adminUsername: readonly string[];
  adminPassword: readonly string[];
} = {
  url: ["GROW_AUTH_ISSUER", "GROW_AUTH_PUBLIC_URL", "CASDOOR_URL"],
  publicUrl: ["GROW_AUTH_PUBLIC_URL"],
  clientId: ["GROW_AUTH_CLIENT_ID"],
  clientSecret: ["GROW_AUTH_CLIENT_SECRET"],
  organization: ["GROW_AUTH_ORG"],
  application: ["GROW_AUTH_APP"],
  redirectUri: ["GROW_AUTH_REDIRECT_URL"],
  adminUsername: ["CASDOOR_ADMIN_USERNAME"],
  adminPassword: ["CASDOOR_ADMIN_PASSWORD"],
};

/** Immutable configuration of {@link CasdoorClient}. */
export class CasdoorConfig implements CommonConfig {
  /** Default endpoint. */
  static readonly DEFAULT_URL = `http://127.0.0.1:${/\d+/.exec(CATALOG_PORT)?.[0] ?? "8080"}`;
  /** Prefix of every environment variable. */
  static readonly ENV_PREFIX = "GROW_CASDOOR_";

  readonly url: string;
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly totalTimeoutMs: number;
  readonly retry: RetryPolicy;
  readonly tls: Readonly<TlsOptions>;
  readonly proxy?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly userAgentSuffix?: string;
  readonly hooks?: Hooks;
  readonly logger?: ClientLogger;
  /** Browser-facing URL (authorize URL); defaults to `url`. */
  readonly publicUrl: string;
  readonly clientId?: string;
  readonly clientSecret?: Secret;
  readonly organization?: string;
  readonly application?: string;
  readonly redirectUri?: string;
  readonly scope: string;
  readonly adminUsername: string;
  readonly adminPassword?: Secret;
  readonly adminOrganization: string;
  readonly adminApplication: string;
  readonly requireVerifiedEmail: boolean;

  /** Applies defaults, validates (throws {@link ConfigError}) and freezes. */
  constructor(options: CasdoorConfigOptions = {}) {
    const common = resolveCommonConfig(options, CasdoorConfig.DEFAULT_URL);
    this.url = common.url;
    this.connectTimeoutMs = common.connectTimeoutMs;
    this.requestTimeoutMs = common.requestTimeoutMs;
    this.totalTimeoutMs = common.totalTimeoutMs;
    this.retry = common.retry;
    this.tls = common.tls;
    this.headers = common.headers;
    if (common.proxy !== undefined) this.proxy = common.proxy;
    if (common.userAgentSuffix !== undefined) this.userAgentSuffix = common.userAgentSuffix;
    if (common.hooks !== undefined) this.hooks = common.hooks;
    if (common.logger !== undefined) this.logger = common.logger;
    this.publicUrl = trimSlash(nonEmpty(options.publicUrl) ?? common.url);
    setIf(this, "clientId", nonEmpty(options.clientId));
    setIf(this, "clientSecret", Secret.from(options.clientSecret));
    setIf(this, "organization", nonEmpty(options.organization));
    setIf(this, "application", nonEmpty(options.application));
    setIf(this, "redirectUri", nonEmpty(options.redirectUri));
    setIf(this, "adminPassword", Secret.from(options.adminPassword));
    this.scope = nonEmpty(options.scope) ?? DEFAULT_SCOPE;
    this.adminUsername = nonEmpty(options.adminUsername) ?? "admin";
    this.adminOrganization = nonEmpty(options.adminOrganization) ?? "built-in";
    this.adminApplication = nonEmpty(options.adminApplication) ?? "app-built-in";
    this.requireVerifiedEmail = options.requireVerifiedEmail ?? true;
    this.validate();
    Object.freeze(this);
  }

  /** Returns `options` when it already is a config, otherwise builds one. */
  static from(options: CasdoorConfigOptions = {}): CasdoorConfig {
    if (options instanceof CasdoorConfig) return options;
    return new CasdoorConfig(options);
  }

  /**
   * Builds a config from the environment. Precedence: explicit `overrides` >
   * `GROW_CASDOOR_<NAME>` > platform/vendor variables ({@link VENDOR_ENV}) > defaults.
   */
  static fromEnv(overrides: CasdoorConfigOptions = {}, env: EnvMap = process.env): CasdoorConfig {
    const reader = new EnvReader(CasdoorConfig.ENV_PREFIX, env);
    const fromEnv: CasdoorConfigOptions = readCommonEnv(reader, VENDOR_ENV);
    const strings: [keyof CasdoorConfigOptions, string, readonly string[]][] = [
      ["publicUrl", "PUBLIC_URL", VENDOR_ENV.publicUrl],
      ["clientId", "CLIENT_ID", VENDOR_ENV.clientId],
      ["organization", "ORG", VENDOR_ENV.organization],
      ["application", "APP", VENDOR_ENV.application],
      ["redirectUri", "REDIRECT_URL", VENDOR_ENV.redirectUri],
      ["scope", "SCOPE", []],
      ["adminUsername", "ADMIN_USERNAME", VENDOR_ENV.adminUsername],
      ["adminOrganization", "ADMIN_ORG", []],
      ["adminApplication", "ADMIN_APP", []],
    ];
    const out = fromEnv as Record<string, unknown>;
    for (const [key, name, vendor] of strings) {
      const value = reader.string(name, vendor);
      if (value !== undefined) out[key] = value;
    }
    const clientSecret = reader.secret("CLIENT_SECRET", VENDOR_ENV.clientSecret);
    if (clientSecret !== undefined) fromEnv.clientSecret = clientSecret;
    const adminPassword = reader.secret("ADMIN_PASSWORD", VENDOR_ENV.adminPassword);
    if (adminPassword !== undefined) fromEnv.adminPassword = adminPassword;
    const verified = reader.bool("REQUIRE_VERIFIED_EMAIL");
    if (verified !== undefined) fromEnv.requireVerifiedEmail = verified;
    const merged = mergeOptions<CasdoorConfigOptions>(fromEnv, overrides);
    return new CasdoorConfig(merged);
  }

  /** Throws {@link ConfigError} when a setting is invalid. */
  validate(): void {
    validateCommonConfig(this);
    if (!/^https?:\/\//i.test(this.publicUrl))
      throw new ConfigError("invalid configuration: publicUrl must be an http(s) URL");
    if (this.clientSecret?.reveal().trim() === "")
      throw new ConfigError("invalid configuration: clientSecret must not be blank");
    if (this.adminPassword?.reveal().trim() === "")
      throw new ConfigError("invalid configuration: adminPassword must not be blank");
  }

  /** Credential values to redact from error messages and logs. */
  knownSecrets(): string[] {
    return secretValues(this.clientSecret, this.adminPassword);
  }

  /** Debug form with every credential redacted. */
  toJSON(): Record<string, unknown> {
    return {
      ...describeCommonConfig(this),
      publicUrl: this.publicUrl,
      clientId: this.clientId ?? null,
      clientSecret: this.clientSecret === undefined ? null : REDACTED,
      organization: this.organization ?? null,
      application: this.application ?? null,
      redirectUri: this.redirectUri ?? null,
      scope: this.scope,
      adminUsername: this.adminUsername,
      adminPassword: this.adminPassword === undefined ? null : REDACTED,
      adminOrganization: this.adminOrganization,
      adminApplication: this.adminApplication,
      requireVerifiedEmail: this.requireVerifiedEmail,
    };
  }

  toString(): string {
    return `CasdoorConfig(${JSON.stringify(this.toJSON())})`;
  }

  [INSPECT](): string {
    return this.toString();
  }
}

/** `undefined` for `undefined`/blank strings. */
function nonEmpty(value: string | undefined): string | undefined {
  return value === undefined || value.trim() === "" ? undefined : value.trim();
}

/** Removes trailing slashes. */
function trimSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

/** Assigns an optional readonly field during construction. */
function setIf<K extends keyof CasdoorConfig>(
  target: CasdoorConfig,
  key: K,
  value: CasdoorConfig[K] | undefined,
): void {
  if (value !== undefined) (target as unknown as Record<string, unknown>)[key as string] = value;
}
