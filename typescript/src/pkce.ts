// Service-owned: PKCE, state and TOTP helpers (no I/O).

import { createHash, createHmac, randomBytes } from "node:crypto";

/** A PKCE pair (RFC 7636, method S256). */
export interface Pkce {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

/** base64url without padding. */
function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Creates a PKCE verifier (64 random characters) and its S256 challenge.
 *
 * @returns The pair; keep the verifier server-side until {@link CasdoorClient.exchangeCode}.
 */
export function createPkce(): Pkce {
  const codeVerifier = base64url(randomBytes(48));
  return { codeVerifier, codeChallenge: pkceChallenge(codeVerifier), codeChallengeMethod: "S256" };
}

/**
 * S256 challenge of a verifier.
 *
 * @param codeVerifier - The PKCE verifier.
 * @returns `base64url(sha256(verifier))`.
 */
export function pkceChallenge(codeVerifier: string): string {
  return base64url(createHash("sha256").update(codeVerifier).digest());
}

/**
 * Random URL-safe value for `state` or `nonce`.
 *
 * @param bytes - Entropy in bytes (default 24).
 * @returns base64url string.
 */
export function randomState(bytes = 24): string {
  return base64url(randomBytes(bytes));
}

/** RFC 4648 base32 decode (TOTP secrets). */
function base32Decode(text: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = text.replace(/=+$/g, "").replace(/\s+/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new TypeError("invalid base32 character in TOTP secret");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * Current TOTP code (RFC 6238, SHA-1, 6 digits, 30 s), for tests and e2e helpers.
 *
 * @param secret - Base32 secret from {@link CasdoorClient.setupTotp}.
 * @param at - Time (default now).
 * @returns The 6-digit code.
 */
export function totpCode(secret: string, at: Date = new Date()): string {
  const counter = Math.floor(at.getTime() / 1000 / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const bin = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(bin % 1_000_000).padStart(6, "0");
}

/**
 * Decodes the payload of a JWT without verifying it (the caller verifies tokens with the `oidc`
 * package; this is only used to read `owner`/`name`/`email_verified` of tokens Casdoor just issued).
 *
 * @param token - A JWT.
 * @returns The payload object, or `undefined` when the token is not a JWT.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const part = token.split(".")[1];
  if (part === undefined || part === "") return undefined;
  try {
    const value: unknown = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return value !== null && typeof value === "object"
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Casdoor user names: `[A-Za-z0-9_-]`, at most 39 characters, no e-mail. */
const USER_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$/;

/**
 * A valid Casdoor user name: the given one when valid, else derived from the e-mail local part.
 *
 * @param email - E-mail address.
 * @param username - Wanted user name.
 * @returns A user name Casdoor accepts.
 */
export function userNameFor(email: string, username?: string): string {
  if (username !== undefined && USER_NAME.test(username)) return username;
  const base = (username ?? email.split("@")[0] ?? "")
    .replace(/[^A-Za-z0-9_-]+/g, "-")
    .replace(/^[-_]+|[-_]+$/g, "")
    .slice(0, 39);
  return base === "" ? "user" : base;
}
