"""Public data types of the Casdoor client."""

from __future__ import annotations

import dataclasses
import datetime
from typing import Any

from ._core import ValidationError

__all__ = [
    "ApplicationInfo",
    "CasdoorUser",
    "Pkce",
    "RoleInfo",
    "SignUpResult",
    "SmtpSettings",
    "TokenSet",
    "TotpSetup",
]


@dataclasses.dataclass(frozen=True)
class TokenSet:
    """OAuth tokens returned by sign-in, refresh and code exchange."""

    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - a token type, not a secret
    refresh_token: str | None = dataclasses.field(default=None, repr=False)
    id_token: str | None = dataclasses.field(default=None, repr=False)
    expires_in: int | None = None
    expires_at: datetime.datetime | None = None
    scope: str | None = None

    def __repr__(self) -> str:  # never print tokens
        return f"TokenSet(token_type={self.token_type!r}, expires_at={self.expires_at!r})"

    @classmethod
    def from_response(cls, body: dict[str, Any], now: datetime.datetime | None = None) -> TokenSet:
        """Build from a token endpoint body."""
        access = body.get("access_token")
        if not isinstance(access, str) or not access:
            raise ValidationError("token: Casdoor returned no access_token")
        expires_in: int | None = None
        expires_at: datetime.datetime | None = None
        raw = body.get("expires_in")
        if isinstance(raw, (int, float)) and raw > 0:
            expires_in = int(raw)
            base = now or datetime.datetime.now(datetime.timezone.utc)
            expires_at = base + datetime.timedelta(seconds=expires_in)

        def opt(key: str) -> str | None:
            value = body.get(key)
            return value if isinstance(value, str) and value else None

        return cls(
            access_token=access,
            token_type=opt("token_type") or "Bearer",
            refresh_token=opt("refresh_token"),
            id_token=opt("id_token"),
            expires_in=expires_in,
            expires_at=expires_at,
            scope=opt("scope"),
        )


@dataclasses.dataclass(frozen=True)
class SignUpResult:
    """Result of :meth:`CasdoorClient.sign_up`."""

    user_id: str
    organization: str
    name: str


@dataclasses.dataclass(frozen=True)
class Pkce:
    """A PKCE pair (RFC 7636, S256)."""

    code_verifier: str = dataclasses.field(repr=False)
    code_challenge: str
    code_challenge_method: str = "S256"


@dataclasses.dataclass(frozen=True)
class TotpSetup:
    """Result of :meth:`CasdoorClient.setup_totp` (show the secret once, never log it)."""

    secret: str = dataclasses.field(repr=False)
    url: str = dataclasses.field(repr=False)
    recovery_codes: list[str] = dataclasses.field(default_factory=list, repr=False)


@dataclasses.dataclass(frozen=True)
class SmtpSettings:
    """SMTP settings for :meth:`CasdoorClient.ensure_email_provider`."""

    host: str
    port: int
    from_address: str
    name: str = "provider-email"
    from_name: str = "Casdoor"
    username: str | None = None
    password: str | None = dataclasses.field(default=None, repr=False)
    disable_ssl: bool = False
    title: str = "Verification code"
    content: str = "Your verification code is %s"


@dataclasses.dataclass(frozen=True)
class ApplicationInfo:
    """Result of :meth:`CasdoorClient.ensure_application`."""

    name: str
    organization: str
    client_id: str
    client_secret: str = dataclasses.field(repr=False)
    redirect_uris: list[str] = dataclasses.field(default_factory=list)
    created: bool = False


@dataclasses.dataclass(frozen=True)
class CasdoorUser:
    """A Casdoor user (subset)."""

    user_id: str
    organization: str
    name: str
    email_verified: bool
    is_forbidden: bool
    created: bool
    id: str | None = None
    email: str | None = None
    display_name: str | None = None


@dataclasses.dataclass(frozen=True)
class RoleInfo:
    """Result entry of :meth:`CasdoorClient.ensure_roles`."""

    name: str
    created: bool
