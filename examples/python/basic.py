"""Health, ping and server version with the synchronous client."""

from __future__ import annotations

import grow_casdoor as sdk


def main() -> None:
    # Reads GROW_CASDOOR_URL, GROW_CASDOOR_TOKEN, timeouts … from the environment.
    with sdk.CasdoorClient.from_env() as client:
        status = client.health()
        print(f"healthy={status.healthy} status={status.status}")
        try:
            print(f"ping: {client.ping():.1f} ms")
            print(f"server version: {client.server_version()}")
        except sdk.AuthenticationError as err:
            print(f"credentials rejected: {err}")
        except sdk.UnsupportedError:
            print("this deployment does not report its version")
        except sdk.CasdoorError as err:
            print(f"failed with {err.code}: {err} (retryable={err.retryable})")


if __name__ == "__main__":
    main()
