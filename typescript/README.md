# @grow-codes/casdoor

TypeScript SDK for [Casdoor](https://grow-codes-packages.github.io/casdoor/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/casdoor
```

```ts
import { CasdoorClient } from "@grow-codes/casdoor";

// Reads GROW_CASDOOR_URL, GROW_CASDOOR_TOKEN, timeouts, TLS and proxy settings.
const client = CasdoorClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: {} }
  console.log(`ping: ${(await client.ping()).toFixed(1)} ms`);
} finally {
  await client.close();
}
```

Every error is a `CasdoorError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/casdoor/testing`.

Documentation: https://grow-codes-packages.github.io/casdoor/ · Licence: Apache-2.0.
Casdoor is a trademark of Casdoor / Casbin organization; this package is not affiliated with or endorsed by it.
