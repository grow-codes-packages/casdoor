"""Casdoor HTTP calls on top of the core transport.

* Envelope calls (``/api/*``): HTTP 200 + ``{"status": "error"}`` → typed error.
* OAuth calls (``/api/login/oauth/*``): form bodies, ``{"error": ...}`` → typed error.
* Cookie jars for flows that need one Casdoor session across calls.
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

from ._core import (
    CancelToken,
    CasdoorError,
    ConfigError,
    HttpTransport,
    Request,
    Response,
    redact_text,
)
from .casdoor_errors import CasdoorReason, envelope_error, oauth_error
from .config import CasdoorConfig

__all__ = ["CasdoorApi", "CookieJar", "error_mapper"]


class CookieJar:
    """Minimal cookie jar for one Casdoor origin."""

    def __init__(self) -> None:
        self._cookies: dict[str, str] = {}

    def header(self) -> str | None:
        """``Cookie`` header value, or ``None`` when empty."""
        if not self._cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def absorb(self, headers: Any) -> None:
        """Store the ``Set-Cookie`` values of a response."""
        values = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
        for raw in values:
            pair = raw.split(";", 1)[0]
            name, sep, value = pair.partition("=")
            if sep and name.strip():
                self._cookies[name.strip()] = value.strip()

    def clear(self) -> None:
        """Forget every cookie."""
        self._cookies.clear()


def _parse(content: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(content or b"null")
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def error_mapper(secrets: Any) -> Any:
    """Transport error mapper: envelopes and OAuth bodies of HTTP error responses."""

    def mapper(error: CasdoorError, resp: Response) -> CasdoorError | None:
        body = _parse(resp.content)
        if body is None:
            return None
        known = secrets()
        op = resp.operation or error.message.split(":", 1)[0]
        if isinstance(body.get("error"), str):
            desc = redact_text(_text(body.get("error_description")), known)
            return oauth_error(op, body["error"], desc, resp.status)
        if body.get("status") == "error":
            msg = redact_text(_text(body.get("msg")), known)
            return envelope_error(op, msg, None, resp.status)
        return None

    return mapper


class CasdoorApi:
    """Casdoor API access shared by the client modules (sync)."""

    def __init__(self, config: CasdoorConfig, transport: HttpTransport) -> None:
        self.config = config
        self.transport = transport
        self._admin_jar = CookieJar()
        self._admin_signed_in = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ config helpers

    def organization(self, op: str, override: str | None = None) -> str:
        org = override or self.config.organization
        if not org:
            raise ConfigError(f"{op}: organization is not configured")
        return org

    def application(self, op: str, override: str | None = None) -> str:
        app = override or self.config.application
        if not app:
            raise ConfigError(f"{op}: application is not configured")
        return app

    def client_id(self, op: str) -> str:
        if not self.config.client_id:
            raise ConfigError(f"{op}: client_id is not configured")
        return self.config.client_id

    def client_secret(self, op: str) -> str:
        if self.config.client_secret is None:
            raise ConfigError(f"{op}: client_secret is not configured")
        return self.config.client_secret.reveal()

    def redact(self, text: str) -> str:
        return redact_text(text, self.config.known_secrets())

    # ------------------------------------------------------------------ calls

    def call(
        self,
        op: str,
        path: str,
        *,
        method: str | None = None,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
        form: Mapping[str, str | None] | None = None,
        auth: str = "none",
        bearer: str | None = None,
        jar: CookieJar | None = None,
        cancel: CancelToken | None = None,
    ) -> dict[str, Any]:
        """Send an envelope call; return the ``status: ok`` envelope or raise a typed error.

        ``auth``: ``none``, ``client`` (HTTP Basic client credentials) or ``admin`` (admin
        session when ``admin_password`` is set, else the client credentials).
        """
        kw: dict[str, Any] = {
            "method": method,
            "params": params,
            "json_body": json_body,
            "form": form,
            "bearer": bearer,
            "cancel": cancel,
        }
        if auth == "admin" and self.config.admin_password is not None:
            self._ensure_admin(op, cancel)
            try:
                return self._send(op, path, auth="none", jar=self._admin_jar, **kw)
            except CasdoorError as err:
                if getattr(err, "casdoor_reason", None) != CasdoorReason.LOGIN_REQUIRED:
                    raise
                self._admin_signed_in = False
                self._ensure_admin(op, cancel)
                return self._send(op, path, auth="none", jar=self._admin_jar, **kw)
        return self._send(op, path, auth=auth, jar=jar, **kw)

    def _send(
        self,
        op: str,
        path: str,
        *,
        method: str | None,
        params: Mapping[str, Any] | None,
        json_body: Any,
        form: Mapping[str, str | None] | None,
        auth: str,
        bearer: str | None,
        jar: CookieJar | None,
        cancel: CancelToken | None,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if auth in ("admin", "client"):
            pair = f"{self.client_id(op)}:{self.client_secret(op)}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(pair).decode()
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        cookie = jar.header() if jar is not None else None
        if cookie is not None:
            headers["Cookie"] = cookie
        content: bytes | None = None
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            content = urlencode({k: v for k, v in form.items() if v is not None}).encode()
        if method is None:
            method = "POST" if json_body is not None or form is not None else "GET"
        req = Request(
            method,
            path,
            operation=op,
            params={k: v for k, v in (params or {}).items() if v is not None},
            json=json_body,
            content=content,
            headers=headers,
        )
        resp = self.transport.request(req, cancel=cancel)
        if jar is not None:
            jar.absorb(resp.headers)
        envelope = _parse(resp.content) or {}
        if envelope.get("status") == "error":
            raise envelope_error(
                op,
                self.redact(_text(envelope.get("msg"))),
                _text(envelope.get("code")) or None,
                resp.status,
            )
        return envelope

    def oauth(
        self,
        op: str,
        path: str,
        form: Mapping[str, str | None],
        cancel: CancelToken | None = None,
    ) -> dict[str, Any]:
        """Post a form to an OAuth endpoint; return its JSON body or raise a typed error."""
        content = urlencode({k: v for k, v in form.items() if v is not None}).encode()
        req = Request(
            "POST",
            path,
            operation=op,
            content=content,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp = self.transport.request(req, cancel=cancel)
        body = _parse(resp.content) or {}
        if isinstance(body.get("error"), str) and body["error"]:
            desc = self.redact(_text(body.get("error_description")))
            raise oauth_error(op, body["error"], desc, resp.status)
        if body.get("status") == "error":
            raise envelope_error(op, self.redact(_text(body.get("msg"))), None, resp.status)
        return body

    def _ensure_admin(self, op: str, cancel: CancelToken | None) -> None:
        with self._lock:
            if self._admin_signed_in:
                return
            password = self.config.admin_password.reveal() if self.config.admin_password else ""
            self._admin_jar.clear()
            self._send(
                f"{op} (admin sign-in)",
                "/api/login",
                method="POST",
                params=None,
                json_body={
                    "application": self.config.admin_application,
                    "organization": self.config.admin_organization,
                    "username": self.config.admin_username,
                    "password": password,
                    "type": "login",
                    "signinMethod": "Password",
                    "autoSignin": False,
                },
                form=None,
                auth="none",
                bearer=None,
                jar=self._admin_jar,
                cancel=cancel,
            )
            if self._admin_jar.header() is None:
                raise ConfigError(f"{op}: Casdoor returned no session cookie for the admin sign-in")
            self._admin_signed_in = True
