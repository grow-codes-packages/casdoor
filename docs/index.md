# Casdoor SDK

[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)
[![CI](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/casdoor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](license.md)

One API for **Casdoor** in five languages: TypeScript, Rust, Go, Python and Java. Every package
has the same functions, options, defaults, error codes and behaviour, tested against a real
`casbin/casdoor:v4.27.1` in Docker.

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [`@grow-codes/casdoor`](https://www.npmjs.com/package/@grow-codes/casdoor) | ![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-typescript.json) |
| Rust | [`grow-casdoor`](https://crates.io/crates/grow-casdoor) | ![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-rust.json) |
| Go | [`github.com/grow-codes-packages/casdoor/go`](https://pkg.go.dev/github.com/grow-codes-packages/casdoor/go) | ![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-go.json) |
| Python | [`grow-casdoor`](https://pypi.org/project/grow-casdoor/) | ![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-python.json) |
| Java | [`codes.grow.packages:casdoor`](https://central.sonatype.com/artifact/codes.grow.packages/casdoor) | ![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/casdoor/badges/coverage-java.json) |

## What you get

- **Client** with health, authenticated ping and server version ([Client](client.md)).
- **Configuration** from code or `GROW_CASDOOR_*` / vendor environment variables, immutable
  and validated ([Configuration](configuration.md)).
- **Retries** with full-jitter backoff and `Retry-After`, connect/request/total timeouts and
  cancellation in every language.
- **Typed errors** with one set of codes across languages ([Error handling](errors.md)).
- **Redaction everywhere**: credentials never appear in errors, logs, hooks or `toString`
  ([Redaction](redaction.md)).
- **Service functions** for the Casdoor API ([Functions](functions.md)).

Start with [Install](install.md) and the [Quickstart](quickstart.md).

!!! note "Independent project"
    This SDK is made by [Grow Codes](https://grow.codes). Casdoor is a trademark of
    its owner (Casdoor / Casbin organization); this project is not affiliated with or endorsed by it. See
    [License & disclaimer](license.md).
