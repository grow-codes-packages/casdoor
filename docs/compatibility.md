# Compatibility

## Runtimes

| Language | Supported | Tested in CI |
| - | - | - |
| TypeScript | Node.js ≥ 22.12, ESM and CommonJS | Node 22, 24 |
| Rust | MSRV 1.88, edition 2021, tokio | stable, 1.88 |
| Go | Go ≥ 1.26 | 1.26, 1.27 |
| Python | ≥ 3.10 | 3.10, 3.13, 3.14 |
| Java | ≥ 17 (Java 17 bytecode) | Temurin 17, 21, 25 |

## Casdoor versions

The integration suite runs against `casbin/casdoor:v4.27.1`. Other versions that expose the same API are
expected to work; report problems as an issue.

## Functions the service or a language cannot serve

Every public function is called against the real service in the Docker suite. Functions that the
service, its emulator or a deployment type cannot serve are listed here with the reason; they are
covered by unit tests and raise `UNSUPPORTED` where the capability is missing.

| Function | Languages | Reason |
| - | - | - |
| `signUp`, `sendEmailVerification`, `verifyEmail`, `forgotPassword`, `resetPassword`, `setupTotp`, `verifyTotp`, `ensure*`, `assignRoles` | Rust, Java | Not in the 0.1 skeletons yet (TypeScript, Go and Python are complete). |
| `recoveryCode` sign-in | Rust, Java | Skeleton signs in with `totpCode` only. |
| `serverVersion` | Rust, Java | Needs the built-in admin session (no admin session in the skeletons): `UNSUPPORTED`. |
| `casdoorReason` on errors | Rust, Java | The skeletons map to the canonical codes and put the reason in the message only. |

Python: `AsyncCasdoorClient` runs the sync calls in a worker thread (`asyncio.to_thread`);
cancelling the task does not abort the HTTP call already in flight.

Real-service suites: `docker/compose.service.yml` runs Casdoor v4.27.1 + PostgreSQL + Mailpit;
`tests/test_real_casdoor.py` / `python/integration/test_flows.py`, `test/real-casdoor.test.ts`
and `go/real_casdoor_test.go` call every function (sign-up, mailed codes, reset, TOTP, PKCE
code exchange, every admin operation) when `GROW_CASDOOR_IT_URL` is set.

## Skipped conformance scenarios

`core.health` step `serverVersion` (capability `version`) is skipped for Rust and Java: it needs
the admin session.

| Scenario | Reason |
| - | - |
| — | none so far |

## Language differences

The API is the same in every language; only the conventions differ (naming, durations, async
model). Java cannot change the process environment, so `loadEnv` sets **system properties**
instead and returns the names it set.
