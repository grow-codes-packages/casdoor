# grow-casdoor (Python)

Python SDK for [Casdoor](https://grow-codes-packages.github.io/casdoor/) by Grow Codes.
Unofficial and community maintained; "Casdoor" is a trademark of its owner (Casdoor / Casbin organization).

```bash
pip install grow-casdoor
```

```python
from grow_casdoor import CasdoorClient, CasdoorConfig

# Reads GROW_CASDOOR_URL, GROW_CASDOOR_TOKEN, ... from the environment.
with CasdoorClient.from_env() as client:
    print(client.health())
    print(client.server_version())
```

The async client has the same methods:

```python
import asyncio
from grow_casdoor import AsyncCasdoorClient

async def main() -> None:
    async with AsyncCasdoorClient.from_env() as client:
        print(await client.health())

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_casdoor`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_casdoor.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/casdoor/ ·
Source: https://github.com/grow-codes-packages/casdoor · Licence: Apache-2.0
