"""Casdoor clients (sync and async).

This file is owned by the service package (generated once by sdk-kit). The sync client holds
the logic (``flows.py``, ``admin.py``); :class:`AsyncCasdoorClient` runs the same calls in a
worker thread (``asyncio.to_thread``), so both expose exactly the same methods.
"""

from __future__ import annotations

import asyncio
import functools
import time
from collections.abc import Callable, Mapping, Sequence
from types import TracebackType
from typing import Any, TypeVar

import httpx

from . import admin, flows
from ._core import (
    CancelledError,
    CancelToken,
    ConfigError,
    HealthStatus,
    HttpTransport,
    Request,
    ResourceRegistry,
    ServiceError,
    TimeoutError,
    UnavailableError,
    UnsupportedError,
)
from .api import CasdoorApi, error_mapper
from .config import CasdoorConfig
from .models import (
    ApplicationInfo,
    CasdoorUser,
    RoleInfo,
    SignUpResult,
    SmtpSettings,
    TokenSet,
    TotpSetup,
)

__all__ = ["AsyncCasdoorClient", "CasdoorClient"]

_T = TypeVar("_T")


class CasdoorClient:
    """Synchronous Casdoor client: user flows for BFFs and idempotent admin operations.

    Every Casdoor ``{"status": "error"}`` answer (HTTP 200) and every OAuth error becomes a typed
    :class:`~grow_casdoor.CasdoorError` subclass with ``casdoor_reason``. Thread-safe; use as a
    context manager or call :meth:`close`.
    """

    def __init__(
        self,
        config: CasdoorConfig | None = None,
        *,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        if config is None:
            config = CasdoorConfig.from_env()
        self.config = config.validate()
        self._resources = ResourceRegistry()
        self._transport = HttpTransport(
            self.config,
            known_secrets=self.config.known_secrets,
            http_transport=http_transport,
            error_mapper=error_mapper(self.config.known_secrets),
        )
        self._api = CasdoorApi(self.config, self._transport)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> CasdoorClient:
        """Build from ``GROW_CASDOOR_*`` and the platform names (``GROW_AUTH_ISSUER``,
        ``GROW_AUTH_CLIENT_ID/SECRET``, ``GROW_AUTH_ORG/APP``, ``CASDOOR_ADMIN_PASSWORD`` …)."""
        return cls(CasdoorConfig.from_env(env, **overrides))

    @property
    def resources(self) -> ResourceRegistry:
        """Background resources stopped by :meth:`close`."""
        return self._resources

    # ------------------------------------------------------------------ core

    def health(self, *, cancel: CancelToken | None = None) -> HealthStatus:
        """``GET /api/health``; never raises for an unhealthy or unreachable service."""
        try:
            resp = self._transport.request(
                Request(
                    "GET", "/api/health", operation="health", raise_for_status=False, max_retries=0
                ),
                cancel=cancel,
            )
        except ServiceError as err:
            if isinstance(err, (CancelledError, ConfigError)):
                raise
            word = (
                "unreachable" if isinstance(err, (UnavailableError, TimeoutError)) else "unhealthy"
            )
            return HealthStatus(healthy=False, status=word, details={"error": err.message})
        try:
            body = resp.json()
        except ServiceError:
            body = None
        status = body.get("status") if isinstance(body, dict) else None
        healthy = resp.ok and status == "ok"
        word = "ok" if healthy else (status if isinstance(status, str) and status else "unhealthy")
        return HealthStatus(healthy=healthy, status=word, details={})

    def ping(self, *, cancel: CancelToken | None = None) -> float:
        """Authenticated round trip with the admin credentials; latency in milliseconds."""
        started = time.monotonic()
        app = self.config.application or self.config.admin_application
        self._api.call(
            "ping",
            "/api/get-application",
            params={"id": f"admin/{app}"},
            auth="admin",
            cancel=cancel,
        )
        return (time.monotonic() - started) * 1000.0

    def server_version(self, *, cancel: CancelToken | None = None) -> str:
        """``/api/get-version-info`` (needs the admin session)."""
        env = self._api.call("server_version", "/api/get-version-info", auth="admin", cancel=cancel)
        data = env.get("data")
        version = data.get("version") if isinstance(data, dict) else None
        if not isinstance(version, str) or not version:
            raise UnsupportedError("server_version: the service does not report a version")
        return version

    # ------------------------------------------------------------------ user flows

    def sign_up(
        self,
        *,
        email: str,
        password: str,
        username: str | None = None,
        display_name: str | None = None,
        email_code: str | None = None,
        cancel: CancelToken | None = None,
    ) -> SignUpResult:
        """Register a user (``/api/signup``); ``email_code`` when the application requires it."""
        return flows.sign_up(
            self._api,
            email=email,
            password=password,
            username=username,
            display_name=display_name,
            email_code=email_code,
            cancel=cancel,
        )

    def sign_in(
        self,
        *,
        username: str,
        password: str,
        totp_code: str | None = None,
        recovery_code: str | None = None,
        redirect_uri: str | None = None,
        cancel: CancelToken | None = None,
    ) -> TokenSet:
        """Headless password sign-in (code flow + PKCE). Raises :class:`MfaRequiredError` and
        :class:`EmailNotVerifiedError`."""
        return flows.sign_in(
            self._api,
            username=username,
            password=password,
            totp_code=totp_code,
            recovery_code=recovery_code,
            redirect_uri=redirect_uri,
            cancel=cancel,
        )

    def refresh(self, refresh_token: str, *, cancel: CancelToken | None = None) -> TokenSet:
        """New tokens from a refresh token."""
        return flows.refresh(self._api, refresh_token, cancel)

    def sign_out(self, token: str, *, cancel: CancelToken | None = None) -> None:
        """End the Casdoor session of the token. Idempotent."""
        flows.sign_out(self._api, token, cancel)

    def send_email_verification(
        self, email: str, *, purpose: str = "auto", cancel: CancelToken | None = None
    ) -> None:
        """Mail a verification code (``purpose``: ``auto``, ``signup`` or ``verify``)."""
        flows.send_email_verification(self._api, email, purpose, cancel)

    def verify_email(self, *, email: str, code: str, cancel: CancelToken | None = None) -> None:
        """Check the code and mark the user's e-mail verified."""
        flows.verify_email(self._api, email=email, code=code, cancel=cancel)

    def forgot_password(self, email: str, *, cancel: CancelToken | None = None) -> None:
        """Mail a password reset code (:class:`NotFoundError` for unknown e-mails)."""
        flows.forgot_password(self._api, email, cancel)

    def reset_password(
        self, *, email: str, code: str, new_password: str, cancel: CancelToken | None = None
    ) -> None:
        """Set a new password with the code from :meth:`forgot_password`."""
        flows.reset_password(
            self._api, email=email, code=code, new_password=new_password, cancel=cancel
        )

    def build_authorize_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        code_challenge: str,
        scope: str | None = None,
        nonce: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> str:
        """Browser authorize URL on ``public_url`` (code flow, PKCE S256)."""
        if self._transport.closed:
            raise CancelledError("build_authorize_url: client is closed")
        return flows.build_authorize_url(
            self._api,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            scope=scope,
            nonce=nonce,
            extra=extra,
        )

    def exchange_code(
        self, *, code: str, code_verifier: str, redirect_uri: str, cancel: CancelToken | None = None
    ) -> TokenSet:
        """Exchange the authorization code from the browser redirect."""
        return flows.exchange_code(
            self._api,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            cancel=cancel,
        )

    def setup_totp(self, access_token: str, *, cancel: CancelToken | None = None) -> TotpSetup:
        """Start TOTP enrollment for the user of the access token."""
        return flows.setup_totp(self._api, access_token, cancel)

    def verify_totp(
        self,
        *,
        access_token: str,
        secret: str,
        code: str,
        recovery_code: str,
        cancel: CancelToken | None = None,
    ) -> None:
        """Verify the first TOTP code, then enable TOTP."""
        flows.verify_totp(
            self._api,
            access_token=access_token,
            secret=secret,
            code=code,
            recovery_code=recovery_code,
            cancel=cancel,
        )

    # ------------------------------------------------------------------ admin

    def ensure_organization(self, name: str, **kw: Any) -> tuple[str, bool]:
        """Create the organization unless it exists; returns ``(name, created)``."""
        return admin.ensure_organization(self._api, name, **kw)

    def ensure_application(self, **kw: Any) -> ApplicationInfo:
        """Create or align the OAuth application; returns its client credentials."""
        return admin.ensure_application(self._api, **kw)

    def ensure_email_provider(
        self, smtp: SmtpSettings, *, cancel: CancelToken | None = None
    ) -> tuple[str, bool]:
        """Create or align an SMTP provider and list it on the configured application."""
        return admin.ensure_email_provider(self._api, smtp, cancel)

    def ensure_roles(
        self,
        names: Sequence[str],
        *,
        organization: str | None = None,
        cancel: CancelToken | None = None,
    ) -> list[RoleInfo]:
        """Create every missing role."""
        return admin.ensure_roles(self._api, names, organization, cancel)

    def ensure_user(self, **kw: Any) -> CasdoorUser:
        """Create or align a user (verified e-mail by default) and assign its roles."""
        return admin.ensure_user(self._api, **kw)

    def assign_roles(
        self,
        user: str,
        roles: Sequence[str],
        *,
        organization: str | None = None,
        cancel: CancelToken | None = None,
    ) -> None:
        """Add a user (``org/name``, name or e-mail) to roles, creating missing roles."""
        admin.assign_roles(self._api, user, roles, organization, cancel)

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Close connections (idempotent)."""
        self._resources.stop_all()
        self._transport.close()

    def __enter__(self) -> CasdoorClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"CasdoorClient(config={self.config!r})"


def _async(method: Callable[..., _T]) -> Callable[..., Any]:
    name = method.__name__

    @functools.wraps(method)
    async def wrapper(self: AsyncCasdoorClient, *args: Any, **kwargs: Any) -> _T:
        return await asyncio.to_thread(getattr(self._sync, name), *args, **kwargs)

    return wrapper


class AsyncCasdoorClient:
    """Asynchronous Casdoor client with the same methods as :class:`CasdoorClient`.

    Calls run in a worker thread. Use ``async with`` or call :meth:`aclose`.
    """

    def __init__(
        self,
        config: CasdoorConfig | None = None,
        *,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._sync = CasdoorClient(config, http_transport=http_transport)
        self.config = self._sync.config

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> AsyncCasdoorClient:
        return cls(CasdoorConfig.from_env(env, **overrides))

    @property
    def resources(self) -> ResourceRegistry:
        return self._sync.resources

    health = _async(CasdoorClient.health)
    ping = _async(CasdoorClient.ping)
    server_version = _async(CasdoorClient.server_version)
    sign_up = _async(CasdoorClient.sign_up)
    sign_in = _async(CasdoorClient.sign_in)
    refresh = _async(CasdoorClient.refresh)
    sign_out = _async(CasdoorClient.sign_out)
    send_email_verification = _async(CasdoorClient.send_email_verification)
    verify_email = _async(CasdoorClient.verify_email)
    forgot_password = _async(CasdoorClient.forgot_password)
    reset_password = _async(CasdoorClient.reset_password)
    exchange_code = _async(CasdoorClient.exchange_code)
    setup_totp = _async(CasdoorClient.setup_totp)
    verify_totp = _async(CasdoorClient.verify_totp)
    ensure_organization = _async(CasdoorClient.ensure_organization)
    ensure_application = _async(CasdoorClient.ensure_application)
    ensure_email_provider = _async(CasdoorClient.ensure_email_provider)
    ensure_roles = _async(CasdoorClient.ensure_roles)
    ensure_user = _async(CasdoorClient.ensure_user)
    assign_roles = _async(CasdoorClient.assign_roles)

    def build_authorize_url(self, **kw: Any) -> str:
        """Same as :meth:`CasdoorClient.build_authorize_url` (no I/O)."""
        return self._sync.build_authorize_url(**kw)

    async def aclose(self) -> None:
        """Close connections (idempotent)."""
        await asyncio.to_thread(self._sync.close)

    close = aclose

    async def __aenter__(self) -> AsyncCasdoorClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncCasdoorClient(config={self.config!r})"
