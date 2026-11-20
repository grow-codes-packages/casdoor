"""Grow Codes SDK for Casdoor.

>>> from grow_casdoor import CasdoorClient
>>> client = CasdoorClient.from_env()  # doctest: +SKIP
>>> tokens = client.sign_in(username="ada@example.test", password="...")  # doctest: +SKIP
"""

from . import _core
from ._core import *  # noqa: F403
from ._version import __version__
from .casdoor_errors import CasdoorReason, EmailNotVerifiedError, MfaRequiredError, casdoor_reason
from .client import AsyncCasdoorClient, CasdoorClient
from .config import DEFAULT_SCOPE, DEFAULT_URL, CasdoorConfig
from .models import (
    ApplicationInfo,
    CasdoorUser,
    Pkce,
    RoleInfo,
    SignUpResult,
    SmtpSettings,
    TokenSet,
    TotpSetup,
)
from .pkce import create_pkce, pkce_challenge, random_state, totp_code

__all__ = [
    "__version__",
    "CasdoorClient",
    "AsyncCasdoorClient",
    "CasdoorConfig",
    "DEFAULT_SCOPE",
    "DEFAULT_URL",
    "CasdoorReason",
    "EmailNotVerifiedError",
    "MfaRequiredError",
    "casdoor_reason",
    "ApplicationInfo",
    "CasdoorUser",
    "Pkce",
    "RoleInfo",
    "SignUpResult",
    "SmtpSettings",
    "TokenSet",
    "TotpSetup",
    "create_pkce",
    "pkce_challenge",
    "random_state",
    "totp_code",
]
__all__ += _core.__all__
