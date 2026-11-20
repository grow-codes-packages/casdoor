"""Idempotent admin operations (platform identity setup, tests).

Casdoor quirks encoded here: ids are always ``owner/name`` (applications, organizations and
providers are owned by ``admin``, roles and users by the organization); updates replace the WHOLE
object (read, change, send back); objects read without admin rights come back with ``***`` in
secret fields and are never written back; user names cannot be e-mail addresses.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Sequence
from typing import Any

from ._core import CancelToken, NotFoundError, ValidationError
from .api import CasdoorApi
from .casdoor_errors import masked_object_error
from .flows import required
from .models import ApplicationInfo, CasdoorUser, RoleInfo, SmtpSettings
from .pkce import user_name_for

_MASK = "***"


def _get(
    api: CasdoorApi, op: str, kind: str, obj_id: str, cancel: CancelToken | None
) -> dict[str, Any] | None:
    data = api.call(op, f"/api/get-{kind}", params={"id": obj_id}, auth="admin", cancel=cancel).get(
        "data"
    )
    return data if isinstance(data, dict) else None


def _add(
    api: CasdoorApi, op: str, kind: str, body: dict[str, Any], cancel: CancelToken | None
) -> None:
    api.call(op, f"/api/add-{kind}", json_body=body, auth="admin", cancel=cancel)


def _update(
    api: CasdoorApi,
    op: str,
    kind: str,
    obj_id: str,
    body: dict[str, Any],
    exempt: Sequence[str],
    cancel: CancelToken | None,
) -> None:
    # Any field still masked would be stored as "***" (users always mask ``password``, which
    # Casdoor ignores on update).
    if any(v == _MASK and k not in exempt for k, v in body.items()):
        raise masked_object_error(op, kind)
    api.call(
        op,
        f"/api/update-{kind}",
        params={"id": obj_id},
        json_body=body,
        auth="admin",
        cancel=cancel,
    )


def _differs(current: dict[str, Any], patch: dict[str, Any]) -> bool:
    return any(
        json.dumps(current.get(k), sort_keys=True) != json.dumps(v, sort_keys=True)
        for k, v in patch.items()
    )


def ensure_organization(
    api: CasdoorApi,
    name: str,
    *,
    display_name: str | None = None,
    password_options: Sequence[str] | None = None,
    enable_totp: bool = True,
    cancel: CancelToken | None = None,
) -> tuple[str, bool]:
    op = "ensure_organization"
    required(op, name=name)
    obj_id = f"admin/{name}"
    patch: dict[str, Any] = {
        "displayName": display_name or name,
        "passwordOptions": list(password_options or ["AtLeast8"]),
        "mfaItems": [{"name": "app", "rule": "Optional"}] if enable_totp else [],
    }
    current = _get(api, op, "organization", obj_id, cancel)
    created = False
    if current is None:
        _add(
            api,
            op,
            "organization",
            {
                "owner": "admin",
                "name": name,
                "passwordType": "bcrypt",
                "countryCodes": ["US"],
                "languages": ["en"],
                "defaultAvatar": "",
                **patch,
            },
            cancel,
        )
        created = True
        current = _get(api, op, "organization", obj_id, cancel)
    if current is not None and _differs(current, patch):
        _update(api, op, "organization", obj_id, {**current, **patch}, [], cancel)
    return name, created


def _provider_ref(name: str) -> dict[str, Any]:
    return {
        "owner": "",
        "name": name,
        "canSignUp": True,
        "canSignIn": True,
        "canUnlink": True,
        "prompted": False,
        "rule": "All",
    }


def ensure_application(
    api: CasdoorApi,
    *,
    name: str | None = None,
    organization: str | None = None,
    display_name: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    redirect_uris: Sequence[str] | None = None,
    grant_types: Sequence[str] | None = None,
    enable_sign_up: bool = True,
    sign_up_email_code: bool = False,
    providers: Sequence[str] | None = None,
    expire_in_hours: int = 1,
    refresh_expire_in_hours: int = 168,
    failed_signin_limit: int = 5,
    failed_signin_frozen_time: int = 15,
    cert: str = "cert-built-in",
    cancel: CancelToken | None = None,
) -> ApplicationInfo:
    op = "ensure_application"
    app_name = api.application(op, name)
    org = api.organization(op, organization)
    obj_id = f"admin/{app_name}"
    signup_items = [
        {"name": "ID", "visible": False, "required": True, "prompted": False, "rule": "Random"},
        {"name": "Username", "visible": True, "required": True, "prompted": False, "rule": "None"},
        {
            "name": "Display name",
            "visible": True,
            "required": False,
            "prompted": False,
            "rule": "None",
        },
        {"name": "Password", "visible": True, "required": True, "prompted": False, "rule": "None"},
        {
            "name": "Confirm password",
            "visible": True,
            "required": True,
            "prompted": False,
            "rule": "None",
        },
        {
            "name": "Email",
            "visible": True,
            "required": True,
            "prompted": False,
            "rule": "Normal" if sign_up_email_code else "No verification",
        },
        {
            "name": "Agreement",
            "visible": False,
            "required": False,
            "prompted": False,
            "rule": "None",
        },
    ]
    patch: dict[str, Any] = {
        "organization": org,
        "displayName": display_name or app_name,
        "redirectUris": list(redirect_uris or []),
        "grantTypes": list(grant_types or ["authorization_code", "refresh_token"]),
        "enablePassword": True,
        "enableSignUp": enable_sign_up,
        "signinMethods": [{"name": "Password", "displayName": "Password", "rule": "All"}],
        "signupItems": signup_items,
        "tokenFormat": "JWT",
        "cert": cert,
        "expireInHours": expire_in_hours,
        "refreshExpireInHours": refresh_expire_in_hours,
        "failedSigninLimit": failed_signin_limit,
        "failedSigninFrozenTime": failed_signin_frozen_time,
    }
    cid = client_id or api.config.client_id
    csecret = client_secret or (
        api.config.client_secret.reveal() if api.config.client_secret else None
    )
    if cid:
        patch["clientId"] = cid
    if csecret:
        patch["clientSecret"] = csecret
    current = _get(api, op, "application", obj_id, cancel)
    created = False
    if current is None:
        _add(
            api,
            op,
            "application",
            {
                "owner": "admin",
                "name": app_name,
                "clientId": cid or secrets.token_hex(10),
                "clientSecret": csecret or secrets.token_hex(20),
                **patch,
            },
            cancel,
        )
        created = True
        current = _get(api, op, "application", obj_id, cancel)
        if current is None:
            raise ValidationError(f"{op}: application {app_name} was not created")
    existing = current.get("providers") if isinstance(current.get("providers"), list) else []
    merged = list(existing or [])
    for provider in providers or []:
        if not any(isinstance(p, dict) and p.get("name") == provider for p in merged):
            merged.append(_provider_ref(provider))
    if len(merged) != len(existing or []):
        patch["providers"] = merged
    if _differs(current, patch):
        current = {**current, **patch}
        _update(api, op, "application", obj_id, current, [], cancel)
    if current.get("clientSecret") == _MASK:
        raise masked_object_error(op, "application")
    uris = current.get("redirectUris")
    return ApplicationInfo(
        name=app_name,
        organization=org,
        client_id=str(current.get("clientId") or ""),
        client_secret=str(current.get("clientSecret") or ""),
        redirect_uris=[str(u) for u in uris] if isinstance(uris, list) else [],
        created=created,
    )


def ensure_email_provider(
    api: CasdoorApi, smtp: SmtpSettings, cancel: CancelToken | None = None
) -> tuple[str, bool]:
    op = "ensure_email_provider"
    required(op, host=smtp.host, from_address=smtp.from_address)
    if smtp.port <= 0:
        raise ValidationError(f"{op}: port must be a positive integer")
    obj_id = f"admin/{smtp.name}"
    patch: dict[str, Any] = {
        "displayName": smtp.name,
        "category": "Email",
        "type": "Default",
        "host": smtp.host,
        "port": smtp.port,
        "disableSsl": smtp.disable_ssl,
        # Casdoor: clientId/clientSecret = SMTP login, clientId2/clientSecret2 = from address/name.
        "clientId": smtp.username or smtp.from_address,
        "clientId2": smtp.from_address,
        "clientSecret2": smtp.from_name,
        "title": smtp.title,
        "content": smtp.content,
    }
    if smtp.password is not None:
        patch["clientSecret"] = smtp.password
    current = _get(api, op, "provider", obj_id, cancel)
    created = False
    if current is None:
        _add(
            api,
            op,
            "provider",
            {"owner": "admin", "name": smtp.name, "clientSecret": "", **patch},
            cancel,
        )
        created = True
    elif _differs(current, patch):
        _update(api, op, "provider", obj_id, {**current, **patch}, [], cancel)
    if api.config.application:
        app_id = f"admin/{api.config.application}"
        app = _get(api, op, "application", app_id, cancel)
        if app is not None:
            providers = app.get("providers") if isinstance(app.get("providers"), list) else []
            if not any(isinstance(p, dict) and p.get("name") == smtp.name for p in providers or []):
                _update(
                    api,
                    op,
                    "application",
                    app_id,
                    {**app, "providers": [*(providers or []), _provider_ref(smtp.name)]},
                    [],
                    cancel,
                )
    return smtp.name, created


def ensure_roles(
    api: CasdoorApi,
    names: Sequence[str],
    organization: str | None = None,
    cancel: CancelToken | None = None,
) -> list[RoleInfo]:
    op = "ensure_roles"
    owner = api.organization(op, organization)
    out: list[RoleInfo] = []
    for name in names:
        required(op, role=name)
        existing = _get(api, op, "role", f"{owner}/{name}", cancel)
        if existing is None:
            _add(
                api,
                op,
                "role",
                {
                    "owner": owner,
                    "name": name,
                    "displayName": name,
                    "users": [],
                    "groups": [],
                    "roles": [],
                    "domains": [],
                    "isEnabled": True,
                },
                cancel,
            )
        out.append(RoleInfo(name=name, created=existing is None))
    return out


def _find_user(
    api: CasdoorApi, op: str, owner: str, user: str, cancel: CancelToken | None
) -> dict[str, Any] | None:
    if "@" in user:
        data = api.call(
            op, "/api/get-user", params={"owner": owner, "email": user}, auth="admin", cancel=cancel
        ).get("data")
        return data if isinstance(data, dict) else None
    obj_id = user if "/" in user else f"{owner}/{user}"
    return _get(api, op, "user", obj_id, cancel)


def _to_user(owner: str, user: dict[str, Any], created: bool) -> CasdoorUser:
    def opt(key: str) -> str | None:
        value = user.get(key)
        return value if isinstance(value, str) and value else None

    name = str(user.get("name") or "")
    return CasdoorUser(
        user_id=f"{owner}/{name}",
        organization=owner,
        name=name,
        email_verified=user.get("emailVerified") is True,
        is_forbidden=user.get("isForbidden") is True,
        created=created,
        id=opt("id"),
        email=opt("email"),
        display_name=opt("displayName"),
    )


def ensure_user(
    api: CasdoorApi,
    *,
    email: str,
    username: str | None = None,
    password: str | None = None,
    display_name: str | None = None,
    email_verified: bool = True,
    roles: Sequence[str] | None = None,
    organization: str | None = None,
    cancel: CancelToken | None = None,
) -> CasdoorUser:
    op = "ensure_user"
    required(op, email=email)
    if password is not None:
        required(op, password=password)
    owner = api.organization(op, organization)
    name = user_name_for(email, username)
    user = _find_user(api, op, owner, email, cancel)
    created = False
    if user is None:
        if password is None:
            raise ValidationError(f"{op}: password is required to create a user")
        body: dict[str, Any] = {
            "owner": owner,
            "name": name,
            "email": email,
            "password": password,
            "displayName": display_name or name,
            "type": "normal-user",
            "emailVerified": email_verified,
        }
        if api.config.application:
            body["signupApplication"] = api.config.application
        _add(api, op, "user", body, cancel)
        created = True
        user = _find_user(api, op, owner, f"{owner}/{name}", cancel)
        if user is None:
            raise ValidationError(f"{op}: user {name} was not created")
    else:
        patch: dict[str, Any] = {"emailVerified": email_verified}
        if display_name is not None:
            patch["displayName"] = display_name
        if password is not None:
            patch["password"] = password
        if password is not None or _differs(user, patch):
            user = {**user, **patch}
            _update(api, op, "user", f"{owner}/{user['name']}", user, ["password"], cancel)
    if roles:
        assign_roles(api, f"{owner}/{user['name']}", roles, owner, cancel)
    return _to_user(owner, user, created)


def assign_roles(
    api: CasdoorApi,
    user: str,
    roles: Sequence[str],
    organization: str | None = None,
    cancel: CancelToken | None = None,
) -> None:
    op = "assign_roles"
    required(op, user=user)
    owner = api.organization(op, organization)
    found = _find_user(api, op, owner, user, cancel)
    if found is None:
        raise NotFoundError(f"{op}: user not found")
    user_id = f"{found.get('owner') or owner}/{found.get('name')}"
    ensure_roles(api, roles, owner, cancel)
    for role in roles:
        obj_id = f"{owner}/{role}"
        current = _get(api, op, "role", obj_id, cancel)
        if current is None:
            continue
        users = [str(u) for u in current.get("users") or []]
        if user_id in users:
            continue
        _update(api, op, "role", obj_id, {**current, "users": [*users, user_id]}, [], cancel)
