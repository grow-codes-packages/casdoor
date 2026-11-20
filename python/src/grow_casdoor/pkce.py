"""PKCE, state, TOTP and JWT payload helpers (no I/O)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from typing import Any

from .models import Pkce

__all__ = [
    "create_pkce",
    "decode_jwt_payload",
    "pkce_challenge",
    "random_state",
    "totp_code",
    "user_name_for",
]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_challenge(code_verifier: str) -> str:
    """S256 challenge of a verifier: ``base64url(sha256(verifier))``."""
    return _b64url(hashlib.sha256(code_verifier.encode()).digest())


def create_pkce() -> Pkce:
    """A new PKCE verifier (64 characters) and its S256 challenge."""
    verifier = _b64url(secrets.token_bytes(48))
    return Pkce(code_verifier=verifier, code_challenge=pkce_challenge(verifier))


def random_state(nbytes: int = 24) -> str:
    """Random URL-safe value for ``state`` or ``nonce``."""
    return _b64url(secrets.token_bytes(nbytes))


def totp_code(secret: str, at: float | None = None) -> str:
    """Current TOTP code (RFC 6238, SHA-1, 6 digits, 30 s) for tests and e2e helpers."""
    clean = re.sub(r"\s+", "", secret).upper().rstrip("=")
    try:
        key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    except (binascii.Error, ValueError):
        raise ValueError("invalid base32 TOTP secret") from None
    counter = int((time.time() if at is None else at) // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """Payload of a JWT without verification (only for tokens Casdoor just issued)."""
    parts = token.split(".")
    if len(parts) < 2 or not parts[1]:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        value = json.loads(raw)
    except (binascii.Error, ValueError):
        return None
    return value if isinstance(value, dict) else None


_USER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$")


def user_name_for(email: str, username: str | None = None) -> str:
    """A Casdoor user name: ``username`` when valid, else derived from the e-mail local part."""
    if username is not None and _USER_NAME.match(username):
        return username
    base = username if username is not None else email.split("@", 1)[0]
    base = re.sub(r"[^A-Za-z0-9_-]+", "-", base).strip("-_")[:39]
    return base or "user"
