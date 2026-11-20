// Service-owned: Casdoor error normalization.
//
// Casdoor answers most API errors with HTTP 200 and `{"status":"error","msg":"…"}` and the OAuth
// endpoints with HTTP 4xx and `{"error":"invalid_grant","error_description":"…"}`. Both are
// mapped here to the canonical SDK errors (SPEC §2.1), with the Casdoor `reason` attached.

import {
  AuthenticationError,
  CasdoorError,
  type ErrorDetails,
  ErrorCode,
  PermissionDeniedError,
  errorForCode,
} from "./core/index.js";

/** Longest vendor text kept in an error message. */
const MAX_TEXT = 300;

/** Machine-readable reasons attached to normalized Casdoor errors. */
export const CasdoorReason = {
  /** Casdoor's misleading "Phone number is invalid" answer to an empty password/code. */
  EmptyCredential: "empty_credential",
  InvalidCredentials: "invalid_credentials",
  LoginRequired: "login_required",
  Forbidden: "forbidden",
  Locked: "locked",
  RateLimited: "rate_limited",
  NotFound: "not_found",
  AlreadyExists: "already_exists",
  NotEnabled: "not_enabled",
  MfaRequired: "mfa_required",
  EmailNotVerified: "email_not_verified",
  MaskedObject: "masked_object",
  InvalidGrant: "invalid_grant",
  InvalidClient: "invalid_client",
  Other: "other",
} as const;
export type CasdoorReason = (typeof CasdoorReason)[keyof typeof CasdoorReason];

/** Extra fields every normalized Casdoor error carries. */
export interface CasdoorErrorInfo {
  /** Normalized reason (see {@link CasdoorReason}). */
  casdoorReason: CasdoorReason;
  /** Casdoor's own error code when it sent one (e.g. `wrong-password`). */
  casdoorCode?: string;
}

/** Sign-in needs a second factor: retry with `totpCode` or `recoveryCode`. */
export class MfaRequiredError extends AuthenticationError {
  /** MFA types Casdoor offers for this user (e.g. `["app"]` for TOTP). */
  readonly mfaTypes: readonly string[];

  constructor(message: string, mfaTypes: readonly string[] = [], details?: ErrorDetails) {
    super(message, details);
    this.mfaTypes = mfaTypes;
    Object.assign(this, { casdoorReason: CasdoorReason.MfaRequired });
  }
}

/** The user signed in but the e-mail address is not verified yet. */
export class EmailNotVerifiedError extends PermissionDeniedError {
  constructor(message: string, details?: ErrorDetails) {
    super(message, details);
    Object.assign(this, { casdoorReason: CasdoorReason.EmailNotVerified });
  }
}

/** Reason attached to `err`, when it is a normalized Casdoor error. */
export function casdoorReason(err: unknown): CasdoorReason | undefined {
  if (!(err instanceof CasdoorError)) return undefined;
  const reason = (err as Partial<CasdoorErrorInfo>).casdoorReason;
  return reason;
}

/** One message rule: pattern → code + reason. Order matters (first match wins). */
const RULES: readonly [RegExp, ErrorCode, CasdoorReason][] = [
  [/phone number is invalid/i, ErrorCode.Validation, CasdoorReason.EmptyCredential],
  [
    /remaining chances|password or code is incorrect|invalid username or password/i,
    ErrorCode.Authentication,
    CasdoorReason.InvalidCredentials,
  ],
  [
    /please (login|sign in) first|access token .*(expired|invalid)|token is invalid|invalid (access )?token/i,
    ErrorCode.Authentication,
    CasdoorReason.LoginRequired,
  ],
  [/too many times|wait for \d+ minutes/i, ErrorCode.RateLimited, CasdoorReason.Locked],
  [/frozen|locked|try again later in/i, ErrorCode.PermissionDenied, CasdoorReason.Locked],
  [
    /only send one code in|too many|too frequent|rate limit/i,
    ErrorCode.RateLimited,
    CasdoorReason.RateLimited,
  ],
  [
    /unauthorized operation|forbidden|no permission|permission denied|not allowed/i,
    ErrorCode.PermissionDenied,
    CasdoorReason.Forbidden,
  ],
  [
    /already exist|duplicate key|already used|is used by|already been taken/i,
    ErrorCode.Conflict,
    CasdoorReason.AlreadyExists,
  ],
  [
    /does not exist|doesn't exist|not exist|not found|please sign up first/i,
    ErrorCode.NotFound,
    CasdoorReason.NotFound,
  ],
  [
    /is not enabled|is disabled|not supported|feature is disabled/i,
    ErrorCode.Unsupported,
    CasdoorReason.NotEnabled,
  ],
];

/** Shortens and cleans a Casdoor message for an error text. */
function clean(text: string): string {
  const one = text.replace(/\s+/g, " ").trim();
  return one.length > MAX_TEXT ? `${one.slice(0, MAX_TEXT)}…` : one;
}

/** Builds the error with the Casdoor info attached. */
function withInfo(
  code: ErrorCode,
  message: string,
  info: CasdoorErrorInfo,
  details: ErrorDetails = {},
): CasdoorError {
  const extra: ErrorDetails = { ...details };
  if (code === ErrorCode.RateLimited && extra.retryAfterMs === undefined) {
    const minutes = /wait for (\d+) minutes/i.exec(message)?.[1];
    const seconds = /in (\d+)\s*s/i.exec(message)?.[1];
    extra.retryAfterMs =
      minutes !== undefined
        ? Number(minutes) * 60_000
        : (seconds === undefined ? 60 : Number(seconds)) * 1000;
    extra.retryable = false;
  }
  const err = errorForCode(code, message, extra);
  Object.assign(err, info);
  return err;
}

/**
 * Maps a Casdoor `{"status":"error","msg":…}` envelope (HTTP 200) to a typed error.
 *
 * @param operation - Operation name for the message (`"signIn"`).
 * @param msg - Casdoor `msg` (redacted by the caller).
 * @param casdoorCode - Casdoor `code` field when present.
 * @param httpStatus - HTTP status of the response (usually 200).
 * @returns The normalized error; never throws.
 */
export function envelopeError(
  operation: string,
  msg: string,
  casdoorCode?: string,
  httpStatus = 200,
): CasdoorError {
  const text = clean(msg === "" ? "Casdoor returned status error" : msg);
  const rule = RULES.find(([re]) => re.test(text));
  const code = rule?.[1] ?? ErrorCode.Validation;
  const reason = rule?.[2] ?? CasdoorReason.Other;
  const hint =
    reason === CasdoorReason.EmptyCredential
      ? " (Casdoor sends this for an empty password or code: check that the value was loaded)"
      : "";
  const info: CasdoorErrorInfo = { casdoorReason: reason };
  if (casdoorCode !== undefined && casdoorCode !== "") info.casdoorCode = casdoorCode;
  return withInfo(code, `${operation}: ${text}${hint}`, info, { httpStatus });
}

/**
 * Maps an OAuth error body (`{"error","error_description"}`) of the token endpoints.
 *
 * @param operation - Operation name.
 * @param error - OAuth `error` value.
 * @param description - OAuth `error_description` (redacted by the caller).
 * @param httpStatus - HTTP status.
 * @returns The normalized error.
 */
export function oauthError(
  operation: string,
  error: string,
  description: string,
  httpStatus: number,
): CasdoorError {
  const text = clean(description === "" ? error : `${error}: ${description}`);
  if (/mfa enabled|multi-factor/i.test(description)) {
    const err = new MfaRequiredError(`${operation}: ${text}`, [], { httpStatus });
    return err;
  }
  const details = { httpStatus };
  switch (error) {
    case "invalid_grant": {
      const rule = RULES.find(([re]) => re.test(description));
      if (rule !== undefined && rule[2] === CasdoorReason.Locked)
        return withInfo(rule[1], `${operation}: ${text}`, { casdoorReason: rule[2] }, details);
      return withInfo(
        ErrorCode.Authentication,
        `${operation}: ${text}`,
        { casdoorReason: CasdoorReason.InvalidGrant },
        details,
      );
    }
    case "invalid_client":
    case "unauthorized_client":
      return withInfo(
        ErrorCode.Authentication,
        `${operation}: ${text}`,
        { casdoorReason: CasdoorReason.InvalidClient },
        details,
      );
    case "unsupported_grant_type":
    case "unsupported_response_type":
      return withInfo(
        ErrorCode.Unsupported,
        `${operation}: ${text}`,
        { casdoorReason: CasdoorReason.NotEnabled },
        details,
      );
    default:
      return withInfo(
        ErrorCode.Validation,
        `${operation}: ${text}`,
        { casdoorReason: CasdoorReason.Other },
        details,
      );
  }
}

/** Error for an object whose secret fields came back masked (`***`). */
export function maskedObjectError(operation: string, kind: string): CasdoorError {
  return withInfo(
    ErrorCode.PermissionDenied,
    `${operation}: Casdoor returned the ${kind} with masked fields; sign in as a global admin (adminPassword) or use the client credentials of an application`,
    { casdoorReason: CasdoorReason.MaskedObject },
  );
}
