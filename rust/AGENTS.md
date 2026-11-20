# AGENTS.md — `casdoor` package (Grow Codes)

Casdoor client for backends-for-frontends (user flows) and identity setup (admin operations).
Token **verification** belongs to the `oidc` package; this package talks to Casdoor's own API.
TypeScript, Go and Python are complete; Java and Rust are skeletons (config, health, ping,
serverVersion, signIn, exchangeCode, refresh, signOut, buildAuthorizeUrl).

## Install

| Language | Install | Import |
| - | - | - |
| TypeScript | `npm i @grow-codes/casdoor` | `import { CasdoorClient } from "@grow-codes/casdoor"` |
| Go | `go get github.com/grow-codes-packages/casdoor/go` | `casdoor "github.com/grow-codes-packages/casdoor/go"` |
| Python | `pip install grow-casdoor` | `from grow_casdoor import CasdoorClient` |
| Rust | `cargo add grow-casdoor` | `use grow_casdoor::CasdoorClient;` |
| Java | `codes.grow.packages:casdoor` | `codes.grow.packages.casdoor.CasdoorClient` |

## Configuration (`fromEnv`)

`GROW_CASDOOR_<NAME>` wins, then the platform names, then the default.

| Setting | Env (in order) | Default |
| - | - | - |
| url (API, in-cluster) | `GROW_CASDOOR_URL`, `GROW_AUTH_ISSUER`, `GROW_AUTH_PUBLIC_URL`, `CASDOOR_URL` | `http://127.0.0.1:8000` |
| publicUrl (browser) | `GROW_CASDOOR_PUBLIC_URL`, `GROW_AUTH_PUBLIC_URL` | url |
| clientId / clientSecret | `GROW_CASDOOR_CLIENT_ID/_SECRET`, `GROW_AUTH_CLIENT_ID/_SECRET` | — |
| organization / application | `GROW_CASDOOR_ORG/_APP`, `GROW_AUTH_ORG/_APP` | — |
| redirectUri | `GROW_CASDOOR_REDIRECT_URL`, `GROW_AUTH_REDIRECT_URL` | — |
| scope | `GROW_CASDOOR_SCOPE` | `openid profile email` |
| adminPassword (admin ops) | `GROW_CASDOOR_ADMIN_PASSWORD`, `CASDOOR_ADMIN_PASSWORD` | — (then client credentials) |
| adminUsername / adminOrganization / adminApplication | `GROW_CASDOOR_ADMIN_USERNAME` (`CASDOOR_ADMIN_USERNAME`), `_ADMIN_ORG`, `_ADMIN_APP` | `admin`, `built-in`, `app-built-in` |
| requireVerifiedEmail | `GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL` | `true` |

Admin calls use the built-in admin **session** when `adminPassword` is set, otherwise HTTP Basic
with the application's client id/secret (Casdoor treats application credentials as admin).

## API (TypeScript names; Go = PascalCase with `ctx` first, Python = snake_case + keyword args)

```ts
const c = CasdoorClient.fromEnv();            // Go: casdoor.NewClientFromEnv()  Python: CasdoorClient.from_env()
await c.health(); await c.ping(); await c.serverVersion(); await c.close();

// user flows (BFF)
await c.signUp({ email, password, username?, displayName?, emailCode? })  // → { userId: "org/name", organization, name }
await c.signIn({ username /* or e-mail */, password, totpCode?, recoveryCode?, redirectUri? }) // → TokenSet
await c.refresh(refreshToken)                  // → TokenSet
await c.signOut(accessOrIdToken)               // idempotent
await c.sendEmailVerification(email, { purpose: "auto" | "signup" | "verify" })
await c.verifyEmail({ email, code })           // checks the code, marks emailVerified
await c.forgotPassword(email)                  // NotFoundError for unknown e-mails (do not reveal)
await c.resetPassword({ email, code, newPassword })
c.buildAuthorizeUrl({ redirectUri, state, codeChallenge, scope?, nonce?, extra? }) // string, on publicUrl
await c.exchangeCode({ code, codeVerifier, redirectUri })  // → TokenSet
await c.setupTotp(accessToken)                 // → { secret, url, recoveryCodes }
await c.verifyTotp({ accessToken, secret, code, recoveryCode }) // verify + enable

// admin (idempotent; identity setup, tests)
await c.ensureOrganization({ name, displayName?, passwordOptions?, enableTotp? }) // → { name, created }
await c.ensureApplication({ name?, organization?, clientId?, clientSecret?, redirectUris?, grantTypes?,
  enableSignUp?, signUpEmailCode?, providers?, expireInHours?, refreshExpireInHours?,
  failedSigninLimit?, failedSigninFrozenTime?, cert? })  // → { name, organization, clientId, clientSecret, redirectUris, created }
await c.ensureEmailProvider({ name?, host, port, from, fromName?, username?, password?, disableSsl?, title?, content? })
await c.ensureRoles(["buyer", "seller"], { organization? })   // → [{ name, created }]
await c.ensureUser({ email, password?, username?, displayName?, emailVerified?, roles?, organization? })
await c.assignRoles(userIdOrNameOrEmail, roles, { organization? })

// helpers
createPkce() /* {codeVerifier, codeChallenge, codeChallengeMethod:"S256"} */; pkceChallenge(v); randomState(); totpCode(secret)
```

`TokenSet { accessToken, refreshToken?, idToken?, tokenType, expiresIn?, expiresAt?, scope? }`.
Go: `SignIn(ctx, SignInInput{...}) (*TokenSet, error)`, `SendEmailVerification(ctx, email, PurposeAuto)`,
`EnsureRoles(ctx, names, org)`, `AssignRoles(ctx, user, roles, org)`, `NewPKCE()`, `TOTPCode(secret, t)`.
Python: `sign_in(username=..., password=..., totp_code=...)`, `ensure_email_provider(SmtpSettings(host=..., port=..., from_address=...))`,
`ensure_organization(name, ...) -> (name, created)`; `AsyncCasdoorClient` has the same methods.

## Errors

Every Casdoor `{"status":"error","msg":…}` (HTTP 200) and OAuth error becomes a typed SDK error
(`CasdoorError` subclasses; Go `*Error` with `errors.Is(err, casdoor.ErrNotFound)`) with a reason
(`err.casdoorReason` / Python `casdoor_reason(err)` / Go `casdoor.ReasonOf(err)`):

| Casdoor says | Error | reason |
| - | - | - |
| `Phone number is invalid in your region …` | VALIDATION | `empty_credential` — an empty password/code was sent (secret not loaded) |
| `password or code is incorrect …` | AUTHENTICATION | `invalid_credentials` |
| `Please login first`, expired token | AUTHENTICATION | `login_required` |
| `… too many times, wait for N minutes` | RATE_LIMITED (retryAfter N min) | `locked` |
| `you can only send one code in 60s` | RATE_LIMITED (retryAfter 60 s) | `rate_limited` |
| `Unauthorized operation`, forbidden | PERMISSION_DENIED | `forbidden` |
| duplicate / already exists | CONFLICT | `already_exists` |
| does not exist / not found | NOT_FOUND | `not_found` |
| `… is not enabled` | UNSUPPORTED | `not_enabled` |
| `NextMfa` on sign-in without a code | `MfaRequiredError` (AUTHENTICATION) | `mfa_required` (`mfaTypes`) |
| token of an unverified e-mail | `EmailNotVerifiedError` (PERMISSION_DENIED) | `email_not_verified` |
| object read back with `***` | PERMISSION_DENIED | `masked_object` |
| OAuth `invalid_grant` / `invalid_client` | AUTHENTICATION | `invalid_grant` / `invalid_client` |

## Casdoor quirks this package handles (do not re-implement)

- Errors come as HTTP 200 + `status:"error"`; every call checks it.
- Ids are `owner/name`; apps, orgs and providers are owned by `admin`, roles and users by the org.
- Updates replace the **whole object**: read, change, send back. Objects read without admin rights
  carry `***` and are never written back.
- User names cannot be e-mails (derived from the local part); users sign in with the e-mail.
- Password sign-in needs `enablePassword` + `signinMethods: Password` (ensureApplication sets both),
  `tokenFormat: JWT` (roles in the token as `[{name}]`), `cert: cert-built-in`.
- `signUp` sends no phone and no e-mail code (the e-mail is verified afterwards with
  `sendEmailVerification` + `verifyEmail`). Casdoor's default application form requires `Phone`
  ("Phone cannot be empty") and its `Email` item rule `None` demands a code ("The verification code
  has not been sent yet!"), both `VALIDATION`. `ensureApplication` writes a form without `Phone` and
  with `Email` rule `No verification`; identity setup that edits an existing application must do
  the same.
- Sign-in is the code flow + PKCE from the server. With TOTP, Casdoor answers `NextMfa` and the
  passcode goes in a **second** `/api/login` call in the same session without the password.
- `mfa/setup/enable` does not check the code: `verifyTotp` verifies first, then enables. The
  organization must offer MFA type `app` (`ensureOrganization` does).
- Reset: `/api/verify-code` and `/api/set-password` must share one Casdoor session (handled).
- `iss` in tokens is the Casdoor origin the token was requested from (in-cluster
  `http://casdoor:8000`), not the public URL: verify with that issuer (oidc package).
- Casdoor sends one verification code per address per 60 s.
