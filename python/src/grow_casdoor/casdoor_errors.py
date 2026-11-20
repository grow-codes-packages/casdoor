"""Casdoor error normalization.

Casdoor answers most API errors with HTTP 200 and ``{"status": "error", "msg": ...}`` and the
OAuth endpoints with HTTP 4xx and ``{"error": "invalid_grant", ...}``. Both are mapped to the
canonical SDK errors with a ``casdoor_reason`` (and ``casdoor_code`` when Casdoor sent one).
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ._core import (
    AuthenticationError,
    CasdoorError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    UnsupportedError,
    ValidationError,
)

__all__ = [
    "CasdoorReason",
    "EmailNotVerifiedError",
    "MfaRequiredError",
    "casdoor_reason",
    "envelope_error",
    "masked_object_error",
    "oauth_error",
]

_MAX_TEXT = 300


class CasdoorReason:
    """Machine-readable reasons attached to normalized Casdoor errors (``err.casdoor_reason``)."""

    EMPTY_CREDENTIAL = "empty_credential"
    INVALID_CREDENTIALS = "invalid_credentials"
    LOGIN_REQUIRED = "login_required"
    FORBIDDEN = "forbidden"
    LOCKED = "locked"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    ALREADY_EXISTS = "already_exists"
    NOT_ENABLED = "not_enabled"
    MFA_REQUIRED = "mfa_required"
    EMAIL_NOT_VERIFIED = "email_not_verified"
    MASKED_OBJECT = "masked_object"
    INVALID_GRANT = "invalid_grant"
    INVALID_CLIENT = "invalid_client"
    OTHER = "other"


class MfaRequiredError(AuthenticationError):
    """Sign-in needs a second factor: retry with ``totp_code`` or ``recovery_code``."""

    def __init__(self, message: str, mfa_types: Sequence[str] = (), **kw: object) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]
        self.mfa_types = list(mfa_types)
        self.casdoor_reason = CasdoorReason.MFA_REQUIRED
        self.casdoor_code: str | None = None


class EmailNotVerifiedError(PermissionDeniedError):
    """The user signed in but the e-mail address is not verified yet."""

    def __init__(self, message: str, **kw: object) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]
        self.casdoor_reason = CasdoorReason.EMAIL_NOT_VERIFIED
        self.casdoor_code: str | None = None


_RULES: list[tuple[re.Pattern[str], type[CasdoorError], str]] = [
    (re.compile(r"phone number is invalid", re.I), ValidationError, CasdoorReason.EMPTY_CREDENTIAL),
    (
        re.compile(
            r"remaining chances|password or code is incorrect|invalid username or password", re.I
        ),
        AuthenticationError,
        CasdoorReason.INVALID_CREDENTIALS,
    ),
    (
        re.compile(
            r"please (login|sign in) first|access token .*(expired|invalid)|token is invalid"
            r"|invalid (access )?token",
            re.I,
        ),
        AuthenticationError,
        CasdoorReason.LOGIN_REQUIRED,
    ),
    (
        re.compile(r"too many times|wait for \d+ minutes", re.I),
        RateLimitError,
        CasdoorReason.LOCKED,
    ),
    (
        re.compile(r"frozen|locked|try again later in", re.I),
        PermissionDeniedError,
        CasdoorReason.LOCKED,
    ),
    (
        re.compile(r"only send one code in|too many|too frequent|rate limit", re.I),
        RateLimitError,
        CasdoorReason.RATE_LIMITED,
    ),
    (
        re.compile(
            r"unauthorized operation|forbidden|no permission|permission denied|not allowed", re.I
        ),
        PermissionDeniedError,
        CasdoorReason.FORBIDDEN,
    ),
    (
        re.compile(r"already exist|duplicate key|already used|is used by|already been taken", re.I),
        ConflictError,
        CasdoorReason.ALREADY_EXISTS,
    ),
    (
        re.compile(r"does not exist|doesn't exist|not exist|not found|please sign up first", re.I),
        NotFoundError,
        CasdoorReason.NOT_FOUND,
    ),
    (
        re.compile(r"is not enabled|is disabled|not supported|feature is disabled", re.I),
        UnsupportedError,
        CasdoorReason.NOT_ENABLED,
    ),
]


def _clean(text: str) -> str:
    one = " ".join(text.split())
    return one[:_MAX_TEXT] + "…" if len(one) > _MAX_TEXT else one


def _build(
    cls: type[CasdoorError],
    message: str,
    reason: str,
    code: str | None = None,
    http_status: int | None = None,
) -> CasdoorError:
    retry_after: float | None = None
    retryable: bool | None = None
    if cls is RateLimitError:
        minutes = re.search(r"wait for (\d+) minutes", message, re.I)
        seconds = re.search(r"in (\d+)\s*s", message, re.I)
        if minutes:
            retry_after = float(minutes.group(1)) * 60
        else:
            retry_after = float(seconds.group(1)) if seconds else 60.0
        retryable = False
    err = cls(message, http_status=http_status, retry_after=retry_after, retryable=retryable)
    err.casdoor_reason = reason  # type: ignore[attr-defined]
    err.casdoor_code = code or None  # type: ignore[attr-defined]
    return err


def casdoor_reason(err: BaseException) -> str | None:
    """The ``casdoor_reason`` of a normalized error, else ``None``."""
    value = getattr(err, "casdoor_reason", None)
    return value if isinstance(value, str) else None


def envelope_error(
    operation: str, msg: str, code: str | None = None, http_status: int | None = 200
) -> CasdoorError:
    """Map a ``{"status": "error", "msg": ...}`` envelope (``msg`` already redacted)."""
    text = _clean(msg or "Casdoor returned status error")
    cls: type[CasdoorError] = ValidationError
    reason = CasdoorReason.OTHER
    for pattern, rule_cls, rule_reason in _RULES:
        if pattern.search(text):
            cls, reason = rule_cls, rule_reason
            break
    hint = (
        " (Casdoor sends this for an empty password or code: check that the value was loaded)"
        if reason == CasdoorReason.EMPTY_CREDENTIAL
        else ""
    )
    return _build(cls, f"{operation}: {text}{hint}", reason, code, http_status)


def oauth_error(operation: str, error: str, description: str, http_status: int) -> CasdoorError:
    """Map an OAuth ``{"error", "error_description"}`` body (description already redacted)."""
    text = _clean(f"{error}: {description}" if description else error)
    message = f"{operation}: {text}"
    if re.search(r"mfa enabled|multi-factor", description, re.I):
        return MfaRequiredError(message, http_status=http_status)
    if error == "invalid_grant":
        for pattern, cls, reason in _RULES:
            if reason == CasdoorReason.LOCKED and pattern.search(description):
                return _build(cls, message, reason, None, http_status)
        return _build(AuthenticationError, message, CasdoorReason.INVALID_GRANT, None, http_status)
    if error in ("invalid_client", "unauthorized_client"):
        return _build(AuthenticationError, message, CasdoorReason.INVALID_CLIENT, None, http_status)
    if error in ("unsupported_grant_type", "unsupported_response_type"):
        return _build(UnsupportedError, message, CasdoorReason.NOT_ENABLED, None, http_status)
    return _build(ValidationError, message, CasdoorReason.OTHER, None, http_status)


def masked_object_error(operation: str, kind: str) -> CasdoorError:
    """Error for an object whose secret fields came back masked (``***``)."""
    return _build(
        PermissionDeniedError,
        f"{operation}: Casdoor returned the {kind} with masked fields; sign in as a global admin "
        "(admin_password) or use the client credentials of an application",
        CasdoorReason.MASKED_OBJECT,
    )
