# Python examples

Install the package, point it at a running Casdoor and run an example:

```bash
pip install grow-casdoor
export GROW_CASDOOR_URL=http://127.0.0.1:8000
export GROW_CASDOOR_TOKEN=...   # when the service needs one
python examples/python/basic.py
```

| File | Shows |
| - | - |
| `basic.py` | sync client: health, ping, server version, error handling |
| `async_basic.py` | async client, cancellation by task |
| `hooks_and_logging.py` | request hooks, the `grow_casdoor` logger, retries and timeouts |
