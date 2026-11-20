// Service-owned: public data types of the Casdoor client.

/** OAuth tokens returned by sign-in, refresh and code exchange. */
export interface TokenSet {
  /** Access token (JWT when the application uses `tokenFormat: JWT`). */
  accessToken: string;
  /** Refresh token, when the application grants `refresh_token`. */
  refreshToken?: string;
  /** OpenID Connect id token. */
  idToken?: string;
  /** Token type, normally `Bearer`. */
  tokenType: string;
  /** Lifetime of the access token in seconds. */
  expiresIn?: number;
  /** Absolute expiry of the access token. */
  expiresAt?: Date;
  /** Granted scopes. */
  scope?: string;
}

/** Input of {@link CasdoorClient.signUp}. */
export interface SignUpInput {
  /** Casdoor user name (`[A-Za-z0-9_-]`, not an e-mail). Derived from the e-mail when omitted. */
  username?: string;
  email: string;
  password: string;
  displayName?: string;
  /** E-mail code from {@link CasdoorClient.sendEmailVerification} when the application requires it. */
  emailCode?: string;
}

/** Result of {@link CasdoorClient.signUp}. */
export interface SignUpResult {
  /** `<organization>/<name>`. */
  userId: string;
  organization: string;
  name: string;
}

/** Input of {@link CasdoorClient.signIn}. */
export interface SignInInput {
  /** User name or e-mail address. */
  username: string;
  password: string;
  /** Current TOTP code when the user has MFA enabled. */
  totpCode?: string;
  /** One recovery code instead of `totpCode`. */
  recoveryCode?: string;
  /** Redirect URI registered on the application (default: config `redirectUri`). */
  redirectUri?: string;
}

/** Input of {@link CasdoorClient.verifyEmail}. */
export interface VerifyEmailInput {
  email: string;
  code: string;
}

/** Input of {@link CasdoorClient.resetPassword}. */
export interface ResetPasswordInput {
  email: string;
  code: string;
  newPassword: string;
}

/** Input of {@link CasdoorClient.buildAuthorizeUrl}. */
export interface AuthorizeUrlInput {
  redirectUri: string;
  state: string;
  /** PKCE S256 challenge (see {@link createPkce}). */
  codeChallenge: string;
  scope?: string;
  nonce?: string;
  /** Extra query parameters (e.g. `prompt`). */
  extra?: Readonly<Record<string, string>>;
}

/** Input of {@link CasdoorClient.exchangeCode}. */
export interface ExchangeCodeInput {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}

/** Result of {@link CasdoorClient.setupTotp}. */
export interface TotpSetup {
  /** Base32 TOTP secret (show once, never log). */
  secret: string;
  /** `otpauth://` URL for QR codes. */
  url: string;
  /** Recovery codes; Casdoor keeps the first one. */
  recoveryCodes: string[];
}

/** Input of {@link CasdoorClient.verifyTotp}. */
export interface VerifyTotpInput {
  /** Access token of the signed-in user. */
  accessToken: string;
  /** Secret returned by {@link CasdoorClient.setupTotp}. */
  secret: string;
  /** Current code from the authenticator app. */
  code: string;
  /** Recovery code returned by {@link CasdoorClient.setupTotp}. */
  recoveryCode: string;
}

/** SMTP settings for {@link CasdoorClient.ensureEmailProvider}. */
export interface SmtpSettings {
  /** Provider name (default `provider-email`). */
  name?: string;
  host: string;
  port: number;
  /** Sender address. */
  from: string;
  /** Sender display name (default `Casdoor`). */
  fromName?: string;
  username?: string;
  password?: string;
  /** Plain SMTP without TLS (Mailpit, MailHog). Default `false`. */
  disableSsl?: boolean;
  /** Mail subject (default `Verification code`). */
  title?: string;
  /** Mail body; `%s` is replaced by the code (default `Your verification code is %s`). */
  content?: string;
}

/** Input of {@link CasdoorClient.ensureOrganization}. */
export interface EnsureOrganizationInput {
  name: string;
  displayName?: string;
  /** Password rules (default `["AtLeast8"]`). */
  passwordOptions?: string[];
  /** Offer TOTP MFA (default `true`). */
  enableTotp?: boolean;
}

/** Input of {@link CasdoorClient.ensureApplication}. */
export interface EnsureApplicationInput {
  /** Application name (default: config `application`). */
  name?: string;
  /** Organization (default: config `organization`). */
  organization?: string;
  displayName?: string;
  /** Client id to pin (default: config `clientId`, else Casdoor generates one). */
  clientId?: string;
  /** Client secret to pin (default: config `clientSecret`, else Casdoor generates one). */
  clientSecret?: string;
  /** Exact redirect URIs. */
  redirectUris?: string[];
  /** Grant types (default `authorization_code`, `refresh_token`). */
  grantTypes?: string[];
  /** Allow self sign-up (default `true`). */
  enableSignUp?: boolean;
  /** Require the e-mail code on sign-up (default `false`: sign up, then verify). */
  signUpEmailCode?: boolean;
  /** Email provider names listed on the application. */
  providers?: string[];
  /** Access token lifetime in hours (default 1). */
  expireInHours?: number;
  /** Refresh token lifetime in hours (default 168). */
  refreshExpireInHours?: number;
  /** Failed sign-ins before lockout (default 5). */
  failedSigninLimit?: number;
  /** Lockout minutes (default 15). */
  failedSigninFrozenTime?: number;
  /** JWT signing certificate (default `cert-built-in`). */
  cert?: string;
}

/** Result of {@link CasdoorClient.ensureApplication}. */
export interface ApplicationInfo {
  name: string;
  organization: string;
  clientId: string;
  /** Client secret (handle as a secret; never log it). */
  clientSecret: string;
  redirectUris: string[];
  created: boolean;
}

/** Input of {@link CasdoorClient.ensureUser}. */
export interface EnsureUserInput {
  email: string;
  /** User name (default: derived from the e-mail local part). */
  username?: string;
  /** Password to set (created users need one; existing users get it reset). */
  password?: string;
  displayName?: string;
  /** Mark the e-mail verified (default `true`). */
  emailVerified?: boolean;
  /** Roles to assign (see {@link CasdoorClient.assignRoles}). */
  roles?: string[];
  /** Organization (default: config `organization`). */
  organization?: string;
}

/** A Casdoor user (subset). */
export interface CasdoorUser {
  /** `<organization>/<name>`. */
  userId: string;
  organization: string;
  name: string;
  id?: string;
  email?: string;
  displayName?: string;
  emailVerified: boolean;
  isForbidden: boolean;
  created: boolean;
}

/** Result of {@link CasdoorClient.ensureRoles}. */
export interface RoleInfo {
  name: string;
  created: boolean;
}
