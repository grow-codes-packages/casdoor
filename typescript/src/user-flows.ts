// Service-owned: user flows used by backends-for-frontends (sign-up, sign-in, tokens, e-mail
// verification, password reset, TOTP). Every call checks the Casdoor envelope.

import { ConfigError, NotFoundError, ValidationError, isCasdoorError } from "./core/index.js";
import { type CasdoorApi, CookieJar } from "./casdoor-api.js";
import { EmailNotVerifiedError, MfaRequiredError } from "./casdoor-errors.js";
import { createPkce, decodeJwtPayload, randomState, userNameFor } from "./pkce.js";
import type {
  AuthorizeUrlInput,
  ExchangeCodeInput,
  ResetPasswordInput,
  SignInInput,
  SignUpInput,
  SignUpResult,
  TokenSet,
  TotpSetup,
  VerifyEmailInput,
  VerifyTotpInput,
} from "./types.js";

/** Casdoor's MFA type for TOTP authenticator apps. */
const TOTP = "app";

/** Throws a client-side `ValidationError` for an empty value (Casdoor would answer "Phone number is invalid"). */
export function required(operation: string, fields: Record<string, string | undefined>): void {
  for (const [name, value] of Object.entries(fields)) {
    if (value === undefined || value.trim() === "") {
      throw new ValidationError(`${operation}: ${name} must not be empty`);
    }
  }
}

/** Optional signal spread. */
function sig(signal?: AbortSignal): { signal?: AbortSignal } {
  return signal === undefined ? {} : { signal };
}

/** Converts a token endpoint body to a {@link TokenSet}. */
export function toTokenSet(body: Record<string, unknown>, now = Date.now()): TokenSet {
  const accessToken = typeof body.access_token === "string" ? body.access_token : "";
  if (accessToken === "") throw new ValidationError("token: Casdoor returned no access_token");
  const out: TokenSet = {
    accessToken,
    tokenType: typeof body.token_type === "string" ? body.token_type : "Bearer",
  };
  if (typeof body.refresh_token === "string" && body.refresh_token !== "")
    out.refreshToken = body.refresh_token;
  if (typeof body.id_token === "string" && body.id_token !== "") out.idToken = body.id_token;
  if (typeof body.scope === "string") out.scope = body.scope;
  const expires = Number(body.expires_in);
  if (Number.isFinite(expires) && expires > 0) {
    out.expiresIn = expires;
    out.expiresAt = new Date(now + expires * 1000);
  }
  return out;
}

/** Refuses tokens of unverified e-mail addresses when the config asks for it. */
function checkVerified(api: CasdoorApi, operation: string, tokens: TokenSet): TokenSet {
  if (!api.config.requireVerifiedEmail) return tokens;
  const claims = decodeJwtPayload(tokens.accessToken);
  const verified = claims?.email_verified ?? claims?.emailVerified;
  if (verified === false) {
    throw new EmailNotVerifiedError(`${operation}: the e-mail address is not verified`);
  }
  return tokens;
}

/** `owner`/`name` of the user an access token belongs to. */
function tokenUser(operation: string, accessToken: string): { owner: string; name: string } {
  const claims = decodeJwtPayload(accessToken);
  const owner = claims?.owner;
  const name = claims?.name;
  if (typeof owner !== "string" || typeof name !== "string" || owner === "" || name === "") {
    throw new ValidationError(
      `${operation}: the access token carries no Casdoor owner/name (use tokenFormat JWT)`,
    );
  }
  return { owner, name };
}

/** Registers a user through `/api/signup`. */
export async function signUp(
  api: CasdoorApi,
  input: SignUpInput,
  signal?: AbortSignal,
): Promise<SignUpResult> {
  const op = "signUp";
  required(op, { email: input.email, password: input.password });
  const organization = api.organization(op);
  const name = userNameFor(input.email, input.username);
  const env = await api.call<string>({
    operation: op,
    method: "POST",
    path: "/api/signup",
    json: {
      application: api.application(op),
      organization,
      username: name,
      name,
      email: input.email,
      emailCode: input.emailCode ?? "",
      password: input.password,
      confirm: input.password,
      displayName: input.displayName ?? name,
      agreement: true,
    },
    jar: new CookieJar(),
    ...sig(signal),
  });
  const userId =
    typeof env.data === "string" && env.data.includes("/") ? env.data : `${organization}/${name}`;
  return { userId, organization, name: userId.split("/")[1] ?? name };
}

/** Headless sign-in: `/api/login` (code + PKCE) then the token endpoint. */
export async function signIn(
  api: CasdoorApi,
  input: SignInInput,
  signal?: AbortSignal,
): Promise<TokenSet> {
  const op = "signIn";
  required(op, { username: input.username, password: input.password });
  const redirectUri = input.redirectUri ?? api.config.redirectUri;
  if (redirectUri === undefined) throw new ConfigError(`${op}: redirectUri is not configured`);
  const pkce = createPkce();
  const mfa: Record<string, string> = {};
  if (input.totpCode !== undefined && input.totpCode !== "") {
    mfa.passcode = input.totpCode;
    mfa.mfaType = TOTP;
  } else if (input.recoveryCode !== undefined && input.recoveryCode !== "") {
    mfa.recoveryCode = input.recoveryCode;
    mfa.mfaType = TOTP;
  }
  const query = {
    clientId: api.clientId(op),
    responseType: "code",
    redirectUri,
    scope: api.config.scope,
    state: randomState(),
    code_challenge: pkce.codeChallenge,
    code_challenge_method: "S256",
  };
  const application = api.application(op);
  const organization = api.organization(op);
  // One Casdoor session for both steps: the password step answers "NextMfa" and remembers the
  // user in the session; the second step sends only the passcode (no username/password).
  const jar = new CookieJar();
  let env = await api.call<string>({
    operation: op,
    method: "POST",
    path: "/api/login",
    query,
    json: {
      application,
      organization,
      username: input.username,
      password: input.password,
      type: "code",
      signinMethod: "Password",
      autoSignin: false,
    },
    jar,
    ...sig(signal),
  });
  if (env.data === "NextMfa") {
    if (mfa.mfaType === undefined) {
      const types = Array.isArray(env.data2)
        ? env.data2
            .map((p: unknown) => (p as { mfaType?: unknown }).mfaType)
            .filter((t): t is string => typeof t === "string")
        : [];
      throw new MfaRequiredError(`${op}: a second factor is required`, types);
    }
    env = await api.call<string>({
      operation: op,
      method: "POST",
      path: "/api/login",
      query,
      json: { application, organization, type: "code", ...mfa },
      jar,
      ...sig(signal),
    });
  }
  if (typeof env.data !== "string" || env.data === "") {
    throw new ValidationError(`${op}: Casdoor returned no authorization code`);
  }
  const tokens = await exchange(
    api,
    op,
    { code: env.data, codeVerifier: pkce.codeVerifier, redirectUri },
    signal,
  );
  return checkVerified(api, op, tokens);
}

/** Token endpoint call for the code grant. */
async function exchange(
  api: CasdoorApi,
  op: string,
  input: ExchangeCodeInput,
  signal?: AbortSignal,
): Promise<TokenSet> {
  const body = await api.oauth(
    op,
    "/api/login/oauth/access_token",
    {
      grant_type: "authorization_code",
      code: input.code,
      code_verifier: input.codeVerifier,
      redirect_uri: input.redirectUri,
      client_id: api.clientId(op),
      client_secret: api.config.clientSecret?.reveal(),
    },
    signal,
  );
  return toTokenSet(body);
}

/** Exchanges an authorization code (browser redirect flow) for tokens. */
export async function exchangeCode(
  api: CasdoorApi,
  input: ExchangeCodeInput,
  signal?: AbortSignal,
): Promise<TokenSet> {
  const op = "exchangeCode";
  required(op, {
    code: input.code,
    codeVerifier: input.codeVerifier,
    redirectUri: input.redirectUri,
  });
  return checkVerified(api, op, await exchange(api, op, input, signal));
}

/** Refreshes tokens (`grant_type=refresh_token`). */
export async function refresh(
  api: CasdoorApi,
  refreshToken: string,
  signal?: AbortSignal,
): Promise<TokenSet> {
  const op = "refresh";
  required(op, { refreshToken });
  const body = await api.oauth(
    op,
    "/api/login/oauth/refresh_token",
    {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: api.clientId(op),
      client_secret: api.config.clientSecret?.reveal(),
      scope: api.config.scope,
    },
    signal,
  );
  return toTokenSet(body);
}

/** Revokes the session of an access token (`/api/logout`). Idempotent. */
export async function signOut(api: CasdoorApi, token: string, signal?: AbortSignal): Promise<void> {
  const op = "signOut";
  required(op, { token });
  try {
    await api.call({
      operation: op,
      method: "POST",
      path: "/api/logout",
      query: { id_token_hint: token },
      ...sig(signal),
    });
  } catch (err) {
    // An expired or already revoked token means the user is already signed out.
    if (isCasdoorError(err, "AUTHENTICATION")) return;
    throw err;
  }
}

/** Sends a verification code to `email` (`/api/send-verification-code`). */
export async function sendEmailVerification(
  api: CasdoorApi,
  email: string,
  purpose: "auto" | "signup" | "verify" = "auto",
  signal?: AbortSignal,
): Promise<void> {
  const op = "sendEmailVerification";
  required(op, { email });
  const send = (method: string, checkUser?: string): Promise<unknown> =>
    api.call({
      operation: op,
      method: "POST",
      path: "/api/send-verification-code",
      form: {
        dest: email,
        type: "email",
        applicationId: `admin/${api.application(op)}`,
        method,
        checkUser,
        captchaType: "none",
        captchaToken: "",
      },
      jar: new CookieJar(),
      ...sig(signal),
    });
  if (purpose === "signup") {
    await send("signup");
    return;
  }
  try {
    await send("login");
  } catch (err) {
    if (purpose === "verify" || !isCasdoorError(err, "NOT_FOUND")) throw err;
    await send("signup");
  }
}

/** Finds a user name by e-mail (client credentials). */
export async function userNameByEmail(
  api: CasdoorApi,
  op: string,
  email: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  const env = await api.call<{ name?: string } | null>({
    operation: op,
    path: "/api/get-user",
    query: { owner: api.organization(op), email },
    auth: "admin",
    ...sig(signal),
  });
  const name = env.data?.name;
  return typeof name === "string" && name !== "" ? name : undefined;
}

/** Checks a code with `/api/verify-code` in the given session. */
async function verifyCode(
  api: CasdoorApi,
  op: string,
  email: string,
  code: string,
  jar: CookieJar,
  signal?: AbortSignal,
): Promise<void> {
  await api.call({
    operation: op,
    method: "POST",
    path: "/api/verify-code",
    json: {
      application: api.application(op),
      organization: api.organization(op),
      username: email,
      name: email,
      code,
      type: "email",
    },
    jar,
    ...sig(signal),
  });
}

/** Verifies the code, then marks the user's e-mail verified (full-object `update-user`). */
export async function verifyEmail(
  api: CasdoorApi,
  input: VerifyEmailInput,
  signal?: AbortSignal,
): Promise<void> {
  const op = "verifyEmail";
  required(op, { email: input.email, code: input.code });
  await verifyCode(api, op, input.email, input.code, new CookieJar(), signal);
  const owner = api.organization(op);
  const env = await api.call<Record<string, unknown> | null>({
    operation: op,
    path: "/api/get-user",
    query: { owner, email: input.email },
    auth: "admin",
    ...sig(signal),
  });
  const user = env.data;
  if (user === null || user === undefined || typeof user.name !== "string") {
    throw new ValidationError(
      `${op}: no user with this e-mail address exists yet (sign up with emailCode instead)`,
    );
  }
  if (user.emailVerified === true) return;
  await api.call({
    operation: op,
    method: "POST",
    path: "/api/update-user",
    query: { id: `${owner}/${user.name}` },
    json: { ...user, emailVerified: true },
    auth: "admin",
    ...sig(signal),
  });
}

/** Sends a password reset code (`method: forget`). Throws `NotFoundError` for unknown e-mails. */
export async function forgotPassword(
  api: CasdoorApi,
  email: string,
  signal?: AbortSignal,
): Promise<void> {
  const op = "forgotPassword";
  required(op, { email });
  const name = await userNameByEmail(api, op, email, signal);
  if (name === undefined) {
    throw new NotFoundError(`${op}: no user with this e-mail address`);
  }
  await api.call({
    operation: op,
    method: "POST",
    path: "/api/send-verification-code",
    form: {
      dest: email,
      type: "email",
      applicationId: `admin/${api.application(op)}`,
      method: "forget",
      checkUser: name,
      captchaType: "none",
      captchaToken: "",
    },
    jar: new CookieJar(),
    ...sig(signal),
  });
}

/** Checks the reset code and sets the new password in the same Casdoor session. */
export async function resetPassword(
  api: CasdoorApi,
  input: ResetPasswordInput,
  signal?: AbortSignal,
): Promise<void> {
  const op = "resetPassword";
  required(op, { email: input.email, code: input.code, newPassword: input.newPassword });
  const name = await userNameByEmail(api, op, input.email, signal);
  if (name === undefined) {
    throw new NotFoundError(`${op}: no user with this e-mail address`);
  }
  const jar = new CookieJar();
  await verifyCode(api, op, input.email, input.code, jar, signal);
  await api.call({
    operation: op,
    method: "POST",
    path: "/api/set-password",
    form: {
      userOwner: api.organization(op),
      userName: name,
      newPassword: input.newPassword,
      code: input.code,
    },
    jar,
    ...sig(signal),
  });
}

/** Browser authorize URL (code flow with PKCE S256) on the public Casdoor URL. */
export function buildAuthorizeUrl(api: CasdoorApi, input: AuthorizeUrlInput): string {
  const op = "buildAuthorizeUrl";
  required(op, {
    redirectUri: input.redirectUri,
    state: input.state,
    codeChallenge: input.codeChallenge,
  });
  const url = new URL(`${api.config.publicUrl}/login/oauth/authorize`);
  const params: Record<string, string | undefined> = {
    client_id: api.clientId(op),
    response_type: "code",
    redirect_uri: input.redirectUri,
    scope: input.scope ?? api.config.scope,
    state: input.state,
    code_challenge: input.codeChallenge,
    code_challenge_method: "S256",
    nonce: input.nonce,
    ...input.extra,
  };
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  return url.toString();
}

/** Starts TOTP enrollment for the user of `accessToken`. */
export async function setupTotp(
  api: CasdoorApi,
  accessToken: string,
  signal?: AbortSignal,
): Promise<TotpSetup> {
  const op = "setupTotp";
  required(op, { accessToken });
  const user = tokenUser(op, accessToken);
  const env = await api.call<{ secret?: string; url?: string; recoveryCodes?: string[] }>({
    operation: op,
    method: "POST",
    path: "/api/mfa/setup/initiate",
    form: { owner: user.owner, name: user.name, mfaType: TOTP },
    bearer: accessToken,
    ...sig(signal),
  });
  const data = env.data ?? {};
  if (typeof data.secret !== "string" || data.secret === "") {
    throw new ValidationError(`${op}: Casdoor returned no TOTP secret`);
  }
  return {
    secret: data.secret,
    url: typeof data.url === "string" ? data.url : "",
    recoveryCodes: Array.isArray(data.recoveryCodes) ? data.recoveryCodes.map(String) : [],
  };
}

/** Verifies the first TOTP code, then enables TOTP (Casdoor's enable does not check the code). */
export async function verifyTotp(
  api: CasdoorApi,
  input: VerifyTotpInput,
  signal?: AbortSignal,
): Promise<void> {
  const op = "verifyTotp";
  required(op, {
    accessToken: input.accessToken,
    secret: input.secret,
    code: input.code,
    recoveryCode: input.recoveryCode,
  });
  const user = tokenUser(op, input.accessToken);
  await api.call({
    operation: op,
    method: "POST",
    path: "/api/mfa/setup/verify",
    form: {
      owner: user.owner,
      name: user.name,
      mfaType: TOTP,
      passcode: input.code,
      secret: input.secret,
    },
    bearer: input.accessToken,
    ...sig(signal),
  });
  await api.call({
    operation: op,
    method: "POST",
    path: "/api/mfa/setup/enable",
    form: {
      owner: user.owner,
      name: user.name,
      mfaType: TOTP,
      secret: input.secret,
      recoveryCodes: input.recoveryCode,
    },
    bearer: input.accessToken,
    ...sig(signal),
  });
}
