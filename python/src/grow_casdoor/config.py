"""Configuration for the Casdoor client.

This file is owned by the service package (generated once by sdk-kit).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any, ClassVar, TypeVar
from urllib.parse import urlsplit

from ._core import BaseConfig, ConfigError, EnvReader, Secret

__all__ = ["DEFAULT_SCOPE", "DEFAULT_URL", "CasdoorConfig"]

#: Default endpoint when neither the config nor the environment sets one.
DEFAULT_URL = "http://127.0.0.1:8000"
#: Default OAuth scopes requested by sign-in and the authorize URL.
DEFAULT_SCOPE = "openid profile email"

_C = TypeVar("_C", bound="CasdoorConfig")


@dataclasses.dataclass(frozen=True, repr=False)
class CasdoorConfig(BaseConfig):
    """Immutable settings for :class:`~grow_casdoor.CasdoorClient`.

    Environment (``from_env``): ``GROW_CASDOOR_<NAME>`` first, then the platform names.

    ========================  ===========================================================
    Field                     Variables (in order)
    ========================  ===========================================================
    ``url``                   ``URL``, ``GROW_AUTH_ISSUER``, ``GROW_AUTH_PUBLIC_URL``,
                              ``CASDOOR_URL``
    ``public_url``            ``PUBLIC_URL``, ``GROW_AUTH_PUBLIC_URL`` (default ``url``)
    ``client_id``             ``CLIENT_ID``, ``GROW_AUTH_CLIENT_ID``
    ``client_secret``         ``CLIENT_SECRET``, ``GROW_AUTH_CLIENT_SECRET``
    ``organization``          ``ORG``, ``GROW_AUTH_ORG``
    ``application``           ``APP``, ``GROW_AUTH_APP``
    ``redirect_uri``          ``REDIRECT_URL``, ``GROW_AUTH_REDIRECT_URL``
    ``scope``                 ``SCOPE`` (default ``openid profile email``)
    ``admin_username``        ``ADMIN_USERNAME``, ``CASDOOR_ADMIN_USERNAME`` (default ``admin``)
    ``admin_password``        ``ADMIN_PASSWORD``, ``CASDOOR_ADMIN_PASSWORD``
    ``admin_organization``    ``ADMIN_ORG`` (default ``built-in``)
    ``admin_application``     ``ADMIN_APP`` (default ``app-built-in``)
    ``require_verified_email`` ``REQUIRE_VERIFIED_EMAIL`` (default ``True``)
    ========================  ===========================================================
    """

    ENV_VENDOR: ClassVar[Mapping[str, tuple[str, ...]]] = {
        "URL": ("GROW_AUTH_ISSUER", "GROW_AUTH_PUBLIC_URL", "CASDOOR_URL"),
        "PUBLIC_URL": ("GROW_AUTH_PUBLIC_URL",),
        "CLIENT_ID": ("GROW_AUTH_CLIENT_ID",),
        "CLIENT_SECRET": ("GROW_AUTH_CLIENT_SECRET",),
        "ORG": ("GROW_AUTH_ORG",),
        "APP": ("GROW_AUTH_APP",),
        "REDIRECT_URL": ("GROW_AUTH_REDIRECT_URL",),
        "ADMIN_USERNAME": ("CASDOOR_ADMIN_USERNAME",),
        "ADMIN_PASSWORD": ("CASDOOR_ADMIN_PASSWORD",),
    }

    url: str = DEFAULT_URL
    public_url: str | None = None
    client_id: str | None = None
    client_secret: Secret | None = None
    organization: str | None = None
    application: str | None = None
    redirect_uri: str | None = None
    scope: str = DEFAULT_SCOPE
    admin_username: str = "admin"
    admin_password: Secret | None = None
    admin_organization: str = "built-in"
    admin_application: str = "app-built-in"
    require_verified_email: bool = True

    def __post_init__(self) -> None:
        super().__post_init__()
        public = self.public_url if self.public_url else self.url
        object.__setattr__(self, "public_url", public.rstrip("/"))

    @property
    def browser_url(self) -> str:
        """Browser-facing URL (``public_url``, always set after construction)."""
        return self.public_url or self.url

    @classmethod
    def _env_values(cls, reader: EnvReader) -> dict[str, Any]:
        values = super()._env_values(reader)
        for field, suffix in (
            ("public_url", "PUBLIC_URL"),
            ("client_id", "CLIENT_ID"),
            ("organization", "ORG"),
            ("application", "APP"),
            ("redirect_uri", "REDIRECT_URL"),
            ("scope", "SCOPE"),
            ("admin_username", "ADMIN_USERNAME"),
            ("admin_organization", "ADMIN_ORG"),
            ("admin_application", "ADMIN_APP"),
        ):
            value = reader.string(suffix, cls.ENV_VENDOR.get(suffix, ()))
            if value is not None:
                values[field] = value
        for field, suffix in (
            ("client_secret", "CLIENT_SECRET"),
            ("admin_password", "ADMIN_PASSWORD"),
        ):
            value = reader.string(suffix, cls.ENV_VENDOR.get(suffix, ()))
            if value is not None:
                values[field] = Secret(value)
        verified = reader.bool("REQUIRE_VERIFIED_EMAIL")
        if verified is not None:
            values["require_verified_email"] = verified
        return values

    def validate(self: _C) -> _C:
        """Common checks plus service rules; raises :class:`ConfigError`."""
        super().validate()
        if urlsplit(self.browser_url).scheme not in ("http", "https"):
            raise ConfigError("config: public_url must be an http(s) URL")
        for name in ("client_secret", "admin_password"):
            value = getattr(self, name)
            if value is not None and not value.reveal().strip():
                raise ConfigError(f"config: {name} must not be blank")
        return self
