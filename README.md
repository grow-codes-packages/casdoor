# Grow Codes SDK for Casdoor

[![CI](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/grow-codes-packages/casdoor?sort=semver)](https://github.com/grow-codes-packages/casdoor/releases)
[![Docs](https://img.shields.io/badge/docs-grow--codes--packages.github.io-blue)](https://grow-codes-packages.github.io/casdoor/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [![npm](https://img.shields.io/npm/v/@grow-codes/casdoor)](https://www.npmjs.com/package/@grow-codes/casdoor) | [![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-typescript.json)](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml) |
| Rust | [![crates.io](https://img.shields.io/crates/v/grow-casdoor)](https://crates.io/crates/grow-casdoor) [![docs.rs](https://img.shields.io/docsrs/grow-casdoor)](https://docs.rs/grow-casdoor) | [![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-rust.json)](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml) |
| Go | [![Go Reference](https://pkg.go.dev/badge/github.com/grow-codes-packages/casdoor/go.svg)](https://pkg.go.dev/github.com/grow-codes-packages/casdoor/go) | [![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-go.json)](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml) |
| Python | [![PyPI](https://img.shields.io/pypi/v/grow-casdoor)](https://pypi.org/project/grow-casdoor/) | [![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-python.json)](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml) |
| Java | [![Maven Central](https://img.shields.io/maven-central/v/codes.grow.packages/casdoor)](https://central.sonatype.com/artifact/codes.grow.packages/casdoor) | [![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-java.json)](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml) |

Open-source client libraries for [Casdoor](#trademarks-and-disclaimer) in **TypeScript, Rust, Go,
Python and Java** — one API, five idiomatic packages, tested against a real Casdoor in Docker.

- **Typed client** with timeouts, retries with jitter, `Retry-After`, cancellation and one error
  model (`CasdoorError` with canonical codes) in every language.
- **Secrets stay secret**: credentials are redacted in `toString`, logs, hooks and error messages.

## Contents

- [Supported service version](#supported-service-version)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Function overview](#function-overview)
- [Testing with Docker](#testing-with-docker)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)
- [Trademarks and disclaimer](#trademarks-and-disclaimer)
- [About Grow Codes](#about-grow-codes)

## Supported service version

Tested in CI against **`casbin/casdoor:v4.27.1`** (the version pinned in the Grow Codes stack catalog). Other
versions with the same API usually work; see [Compatibility](#compatibility) and
[docs/compatibility.md](docs/compatibility.md).

## Install

| Language | Package | Install |
| - | - | - |
| TypeScript (Node.js ≥ 22.12) | `@grow-codes/casdoor` | `npm install @grow-codes/casdoor` |
| Rust (MSRV 1.88) | `grow-casdoor` | `cargo add grow-casdoor` |
| Go (1.26+) | `github.com/grow-codes-packages/casdoor/go` | `go get github.com/grow-codes-packages/casdoor/go` |
| Python (≥ 3.10) | `grow-casdoor` | `pip install grow-casdoor` |
| Java (17+) | `codes.grow.packages:casdoor` | see below |

Maven:

```xml
<dependency>
  <groupId>codes.grow.packages</groupId>
  <artifactId>casdoor</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("codes.grow.packages:casdoor:0.1.0")
```

## Quickstart

Every package reads its configuration from the environment (`GROW_CASDOOR_URL` or
`GROW_AUTH_ISSUER`, `GROW_AUTH_CLIENT_ID/SECRET`, …, see [Configuration](#configuration)) or from an explicit config
object. The examples check the service health and make one authenticated call.

### TypeScript

```ts
import { CasdoorClient } from "@grow-codes/casdoor";

const client = CasdoorClient.fromEnv();
try {
  const health = await client.health();
  console.log(health.healthy, health.status);
  console.log("latency ms:", await client.ping());
} finally {
  await client.close();
}
```

### Rust

```rust
use grow_casdoor::CasdoorClient;

#[tokio::main]
async fn main() -> Result<(), grow_casdoor::Error> {
    let client = CasdoorClient::from_env()?;
    let health = client.health().await?;
    println!("{} {}", health.healthy, health.status);
    println!("latency: {:?}", client.ping().await?);
    client.close().await;
    Ok(())
}
```

### Go

```go
package main

import (
	"context"
	"fmt"
	"log"

	casdoor "github.com/grow-codes-packages/casdoor/go"
)

func main() {
	ctx := context.Background()
	client, err := casdoor.NewClientFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	health, err := client.Health(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(health.Healthy, health.Status)
}
```

### Python

```python
from grow_casdoor import CasdoorClient

with CasdoorClient.from_env() as client:
    health = client.health()
    print(health.healthy, health.status)
    print("latency ms:", client.ping())
```

Async code uses `AsyncCasdoorClient` with the same methods (`async with`, `await client.health()`).

### Java

```java
import codes.grow.packages.casdoor.CasdoorClient;

try (CasdoorClient client = CasdoorClient.fromEnv()) {
    var health = client.health();
    System.out.println(health.healthy() + " " + health.status());
    System.out.println("latency ms: " + client.ping());
}
```

More complete programs live in [examples/](examples/) — one folder per language.

## Configuration

All settings can be passed in code or through environment variables. Precedence: **explicit value >
`GROW_CASDOOR_*` variable > vendor variable > default.** A present but invalid value raises a
`ConfigError` that names the variable (never its value).

| Setting | Environment variable | Default |
| - | - | - |
| `url` | `GROW_CASDOOR_URL`, `GROW_AUTH_ISSUER`, `GROW_AUTH_PUBLIC_URL` | `http://127.0.0.1:8000` |
| `publicUrl` | `GROW_CASDOOR_PUBLIC_URL`, `GROW_AUTH_PUBLIC_URL` | `url` |
| `clientId` / `clientSecret` | `GROW_CASDOOR_CLIENT_ID` / `_CLIENT_SECRET`, `GROW_AUTH_CLIENT_ID` / `_SECRET` | none |
| `organization` / `application` | `GROW_CASDOOR_ORG` / `_APP`, `GROW_AUTH_ORG` / `_APP` | none |
| `redirectUri` | `GROW_CASDOOR_REDIRECT_URL`, `GROW_AUTH_REDIRECT_URL` | none |
| `scope` | `GROW_CASDOOR_SCOPE` | `openid profile email` |
| `adminPassword` | `GROW_CASDOOR_ADMIN_PASSWORD`, `CASDOOR_ADMIN_PASSWORD` | none (admin calls then use the client credentials) |
| `requireVerifiedEmail` | `GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL` | `true` |
| `connectTimeout` | `GROW_CASDOOR_CONNECT_TIMEOUT` | 10 s |
| `requestTimeout` (per attempt) | `GROW_CASDOOR_REQUEST_TIMEOUT` | 30 s |
| `totalTimeout` (including retries) | `GROW_CASDOOR_TOTAL_TIMEOUT` | 120 s |
| `retry.maxRetries` | `GROW_CASDOOR_MAX_RETRIES` | 3 |
| `tls.caCertPath` | `GROW_CASDOOR_CA_CERT` | system roots |
| `tls.clientCertPath` / `tls.clientKeyPath` | `GROW_CASDOOR_CLIENT_CERT` / `GROW_CASDOOR_CLIENT_KEY` | none |
| `tls.insecureSkipVerify` (tests only) | `GROW_CASDOOR_INSECURE_SKIP_VERIFY` | `false` |
| `proxy` | `GROW_CASDOOR_PROXY` | none (environment proxies are ignored) |
| `headers`, `userAgentSuffix`, `hooks`, `logger` | — | none |

Vendor variables that are also read: `GROW_AUTH_ISSUER`/`GROW_AUTH_PUBLIC_URL`, `GROW_AUTH_CLIENT_ID`, `GROW_AUTH_CLIENT_SECRET`, `GROW_AUTH_ORG`, `GROW_AUTH_APP`, `GROW_AUTH_REDIRECT_URL`, `CASDOOR_ADMIN_PASSWORD`, `GROW_CASDOOR_*`.

Durations accept milliseconds (`1500`) or units (`500ms`, `10s`, `1m30s`); booleans accept
`true/false/1/0/yes/no/on/off`. Field names follow each language's convention
(`request_timeout` in Python and Rust, `RequestTimeout` in Go). The full reference is in the
[documentation](https://grow-codes-packages.github.io/casdoor/).

## Function overview

<!-- service:function-overview — the service fills this section; keep the heading. -->

The same functions exist in every language, named per language convention (`getString` in
TypeScript and Java, `get_string` in Python and Rust, `GetString` in Go).

| Area | Functions | Description |
| - | - | - |
| Client | `health`, `ping`, `serverVersion`, `close` | liveness, authenticated round trip, server version, shutdown |
| User flows | `signUp`, `signIn`, `refresh`, `signOut`, `sendEmailVerification`, `verifyEmail`, `forgotPassword`, `resetPassword`, `buildAuthorizeUrl`, `exchangeCode`, `setupTotp`, `verifyTotp` | backend-for-frontend sign-up/sign-in (code + PKCE), tokens, e-mail codes, password reset, TOTP |
| Admin | `ensureOrganization`, `ensureApplication`, `ensureEmailProvider`, `ensureRoles`, `ensureUser`, `assignRoles` | idempotent identity setup (full-object updates, masked-field guard) |
| Helpers | `createPkce`, `pkceChallenge`, `randomState`, `totpCode` | PKCE S256, state/nonce, TOTP codes for tests |

Rust and Java implement the client, `signIn`, `exchangeCode`, `refresh`, `signOut` and
`buildAuthorizeUrl` so far (see `docs/compatibility.md`). Exact API: `docs/agents-api.md`
(shipped as `AGENTS.md` in every package).

<!-- /service:function-overview -->

## Testing with Docker

The integration suite runs every public function against a real Casdoor (`casbin/casdoor:v4.27.1`) in Docker.
Each language package is packed and installed into a separate consumer project first, so the tests
use the package exactly as you would.

```sh
make test-docker                     # all five languages
make test-docker LANGS="go python"   # a subset
```

No host ports are published and every run uses its own Compose project, so runs never collide; the
stack is always removed afterwards (`docker compose down -v`). Unit tests need no Docker:
`make test` or `make coverage`.

## Compatibility

| | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Runtime | Node.js ≥ 22.12, ESM + CJS | stable, MSRV 1.88 | 1.26, 1.27 | 3.10 – 3.14 | 17, 21, 25 |
| Async | `Promise` + `AbortSignal` | `async` (tokio), `blocking` feature | `context.Context` | sync + `asyncio` | sync + `CompletableFuture` |
| Casdoor | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` |

Functions that Casdoor (or its emulator) cannot serve are listed with the reason in
[docs/compatibility.md](docs/compatibility.md).

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) first. All five languages keep the same API; a change lands in all of them
together. Parts of this repository are generated by
[sdk-kit](https://github.com/grow-codes-packages/sdk-kit) and changed there.

## Security

Please report vulnerabilities privately to [opensource@grow.codes](mailto:opensource@grow.codes).
See [SECURITY.md](SECURITY.md).

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.

## Trademarks and disclaimer

This is an independent, community-maintained project. It is **not affiliated with, endorsed or
sponsored by its owner (Casdoor / Casbin organization)**. Casdoor is a trademark of Casdoor / Casbin organization; it is used here only to name the
service this SDK connects to. The Casdoor server is licensed separately by its owner
(Apache-2.0 (Casdoor, casdoor.org)).

The software is provided "AS IS", without warranties or conditions of any kind. Grow Codes is not
responsible for any damage, data loss, security incident, outage or cost that results from using it.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## About Grow Codes

This SDK is built and maintained by [Grow Codes](https://grow.codes). Grow Codes publishes the
client libraries it builds as open source in the
[grow-codes-packages](https://github.com/grow-codes-packages) organisation, generated from one
shared kit so that every service and every language behaves the same way. Learn more at
[grow.codes](https://grow.codes).
