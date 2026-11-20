"""User flows for backends-for-frontends (sign-up, sign-in, tokens, e-mail verification,
password reset, TOTP). Every call checks the Casdoor envelope."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from ._core import AuthenticationError, CancelToken, ConfigError, NotFoundError, ValidationError
from .api import CasdoorApi, CookieJar
from .casdoor_errors import EmailNotVerifiedError, MfaRequiredError
from .models import SignUpResult, TokenSet, TotpSetup
from .pkce import create_pkce, decode_jwt_payload, random_state, user_name_for

_TOTP = "app"


def required(op: str, **fields: str | None) -> None:
    """Client-side ``ValidationError`` for empty values (Casdoor would answer "Phone number is
    invalid")."""
    for name, value in fields.items():
        if value is None or not value.strip():
            raise ValidationError(f"{op}: {name} must not be empty")


def _check_verified(api: CasdoorApi, op: str, tokens: TokenSet) -> TokenSet:
    if not api.config.require_verified_email:
        return tokens
    claims = decode_jwt_payload(tokens.access_token) or {}
    verified = claims.get("email_verified", claims.get("emailVerified"))
    if verified is False:
        raise EmailNotVerifiedError(f"{op}: the e-mail address is not verified")
    return tokens


def _token_user(op: str, access_token: str) -> tuple[str, str]:
    claims = decode_jwt_payload(access_token) or {}
    owner, name = claims.get("owner"), claims.get("name")
    if not isinstance(owner, str) or not isinstance(name, str) or not owner or not name:
        raise ValidationError(
            f"{op}: the access token carries no Casdoor owner/name (use tokenFormat JWT)"
        )
    return owner, name


def sign_up(
    api: CasdoorApi,
    *,
    email: str,
    password: str,
    username: str | None = None,
    display_name: str | None = None,
    email_code: str | None = None,
    cancel: CancelToken | None = None,
) -> SignUpResult:
    op = "sign_up"
    required(op, email=email, password=password)
    org = api.organization(op)
    name = user_name_for(email, username)
    env = api.call(
        op,
        "/api/signup",
        json_body={
            "application": api.application(op),
            "organization": org,
            "username": name,
            "name": name,
            "email": email,
            "emailCode": email_code or "",
            "password": password,
            "confirm": password,
            "displayName": display_name or name,
            "agreement": True,
        },
        jar=CookieJar(),
        cancel=cancel,
    )
    data = env.get("data")
    user_id = data if isinstance(data, str) and "/" in data else f"{org}/{name}"
    return SignUpResult(user_id=user_id, organization=org, name=user_id.split("/", 1)[1])


def _exchange(
    api: CasdoorApi,
    op: str,
    code: str,
    verifier: str,
    redirect_uri: str,
    cancel: CancelToken | None,
) -> TokenSet:
    secret = api.config.client_secret.reveal() if api.config.client_secret else None
    body = api.oauth(
        op,
        "/api/login/oauth/access_token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
            "client_id": api.client_id(op),
            "client_secret": secret,
        },
        cancel,
    )
    return TokenSet.from_response(body)


def sign_in(
    api: CasdoorApi,
    *,
    username: str,
    password: str,
    totp_code: str | None = None,
    recovery_code: str | None = None,
    redirect_uri: str | None = None,
    cancel: CancelToken | None = None,
) -> TokenSet:
    op = "sign_in"
    required(op, username=username, password=password)
    redirect = redirect_uri or api.config.redirect_uri
    if not redirect:
        raise ConfigError(f"{op}: redirect_uri is not configured")
    pkce = create_pkce()
    application, organization = api.application(op), api.organization(op)
    params = {
        "clientId": api.client_id(op),
        "responseType": "code",
        "redirectUri": redirect,
        "scope": api.config.scope,
        "state": random_state(),
        "code_challenge": pkce.code_challenge,
        "code_challenge_method": "S256",
    }
    mfa: dict[str, Any] = {}
    if totp_code:
        mfa = {"passcode": totp_code, "mfaType": _TOTP}
    elif recovery_code:
        mfa = {"recoveryCode": recovery_code, "mfaType": _TOTP}
    # One Casdoor session for both steps: the password step answers "NextMfa" and remembers the
    # user in the session; the second step sends only the passcode (no username/password).
    jar = CookieJar()
    env = api.call(
        op,
        "/api/login",
        method="POST",
        params=params,
        json_body={
            "application": application,
            "organization": organization,
            "username": username,
            "password": password,
            "type": "code",
            "signinMethod": "Password",
            "autoSignin": False,
        },
        jar=jar,
        cancel=cancel,
    )
    data = env.get("data")
    if data == "NextMfa":
        if not mfa:
            props = env.get("data2")
            types = (
                [p.get("mfaType") for p in props if isinstance(p, dict)]
                if isinstance(props, list)
                else []
            )
            raise MfaRequiredError(
                f"{op}: a second factor is required", [t for t in types if isinstance(t, str)]
            )
        env = api.call(
            op,
            "/api/login",
            method="POST",
            params=params,
            json_body={
                "application": application,
                "organization": organization,
                "type": "code",
                **mfa,
            },
            jar=jar,
            cancel=cancel,
        )
        data = env.get("data")
    if not isinstance(data, str) or not data:
        raise ValidationError(f"{op}: Casdoor returned no authorization code")
    tokens = _exchange(api, op, data, pkce.code_verifier, redirect, cancel)
    return _check_verified(api, op, tokens)


def exchange_code(
    api: CasdoorApi,
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    cancel: CancelToken | None = None,
) -> TokenSet:
    op = "exchange_code"
    required(op, code=code, code_verifier=code_verifier, redirect_uri=redirect_uri)
    return _check_verified(api, op, _exchange(api, op, code, code_verifier, redirect_uri, cancel))


def refresh(api: CasdoorApi, refresh_token: str, cancel: CancelToken | None = None) -> TokenSet:
    op = "refresh"
    required(op, refresh_token=refresh_token)
    secret = api.config.client_secret.reveal() if api.config.client_secret else None
    body = api.oauth(
        op,
        "/api/login/oauth/refresh_token",
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": api.client_id(op),
            "client_secret": secret,
            "scope": api.config.scope,
        },
        cancel,
    )
    return TokenSet.from_response(body)


def sign_out(api: CasdoorApi, token: str, cancel: CancelToken | None = None) -> None:
    op = "sign_out"
    required(op, token=token)
    try:
        api.call(op, "/api/logout", method="POST", params={"id_token_hint": token}, cancel=cancel)
    except AuthenticationError:
        return  # an expired or revoked token is already signed out


def _send_code(
    api: CasdoorApi,
    op: str,
    email: str,
    method: str,
    check_user: str | None,
    cancel: CancelToken | None,
) -> None:
    api.call(
        op,
        "/api/send-verification-code",
        form={
            "dest": email,
            "type": "email",
            "applicationId": f"admin/{api.application(op)}",
            "method": method,
            "checkUser": check_user,
            "captchaType": "none",
            "captchaToken": "",
        },
        jar=CookieJar(),
        cancel=cancel,
    )


def send_email_verification(
    api: CasdoorApi, email: str, purpose: str = "auto", cancel: CancelToken | None = None
) -> None:
    op = "send_email_verification"
    required(op, email=email)
    if purpose not in ("auto", "signup", "verify"):
        raise ValidationError(f"{op}: purpose must be auto, signup or verify")
    if purpose == "signup":
        _send_code(api, op, email, "signup", None, cancel)
        return
    try:
        _send_code(api, op, email, "login", None, cancel)
    except NotFoundError:
        if purpose == "verify":
            raise
        _send_code(api, op, email, "signup", None, cancel)


def user_by_email(
    api: CasdoorApi, op: str, email: str, cancel: CancelToken | None = None
) -> dict[str, Any] | None:
    env = api.call(
        op,
        "/api/get-user",
        params={"owner": api.organization(op), "email": email},
        auth="admin",
        cancel=cancel,
    )
    data = env.get("data")
    return data if isinstance(data, dict) and isinstance(data.get("name"), str) else None


def _verify_code(
    api: CasdoorApi, op: str, email: str, code: str, jar: CookieJar, cancel: CancelToken | None
) -> None:
    api.call(
        op,
        "/api/verify-code",
        json_body={
            "application": api.application(op),
            "organization": api.organization(op),
            "username": email,
            "name": email,
            "code": code,
            "type": "email",
        },
        jar=jar,
        cancel=cancel,
    )


def verify_email(
    api: CasdoorApi, *, email: str, code: str, cancel: CancelToken | None = None
) -> None:
    op = "verify_email"
    required(op, email=email, code=code)
    _verify_code(api, op, email, code, CookieJar(), cancel)
    user = user_by_email(api, op, email, cancel)
    if user is None:
        raise ValidationError(
            f"{op}: no user with this e-mail address exists yet (sign up with email_code instead)"
        )
    if user.get("emailVerified") is True:
        return
    owner = api.organization(op)
    api.call(
        op,
        "/api/update-user",
        params={"id": f"{owner}/{user['name']}"},
        json_body={**user, "emailVerified": True},
        auth="admin",
        cancel=cancel,
    )


def forgot_password(api: CasdoorApi, email: str, cancel: CancelToken | None = None) -> None:
    op = "forgot_password"
    required(op, email=email)
    user = user_by_email(api, op, email, cancel)
    if user is None:
        raise NotFoundError(f"{op}: no user with this e-mail address")
    _send_code(api, op, email, "forget", str(user["name"]), cancel)


def reset_password(
    api: CasdoorApi, *, email: str, code: str, new_password: str, cancel: CancelToken | None = None
) -> None:
    op = "reset_password"
    required(op, email=email, code=code, new_password=new_password)
    user = user_by_email(api, op, email, cancel)
    if user is None:
        raise NotFoundError(f"{op}: no user with this e-mail address")
    jar = CookieJar()
    _verify_code(api, op, email, code, jar, cancel)
    api.call(
        op,
        "/api/set-password",
        form={
            "userOwner": api.organization(op),
            "userName": str(user["name"]),
            "newPassword": new_password,
            "code": code,
        },
        jar=jar,
        cancel=cancel,
    )


def build_authorize_url(
    api: CasdoorApi,
    *,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str | None = None,
    nonce: str | None = None,
    extra: dict[str, str] | None = None,
) -> str:
    op = "build_authorize_url"
    required(op, redirect_uri=redirect_uri, state=state, code_challenge=code_challenge)
    params: dict[str, str] = {
        "client_id": api.client_id(op),
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope or api.config.scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if nonce:
        params["nonce"] = nonce
    params.update(extra or {})
    return f"{api.config.browser_url}/login/oauth/authorize?{urlencode(params)}"


def setup_totp(api: CasdoorApi, access_token: str, cancel: CancelToken | None = None) -> TotpSetup:
    op = "setup_totp"
    required(op, access_token=access_token)
    owner, name = _token_user(op, access_token)
    env = api.call(
        op,
        "/api/mfa/setup/initiate",
        form={"owner": owner, "name": name, "mfaType": _TOTP},
        bearer=access_token,
        cancel=cancel,
    )
    data = env.get("data") if isinstance(env.get("data"), dict) else {}
    secret = data.get("secret") if isinstance(data, dict) else None
    if not isinstance(secret, str) or not secret:
        raise ValidationError(f"{op}: Casdoor returned no TOTP secret")
    codes = data.get("recoveryCodes") if isinstance(data, dict) else None
    return TotpSetup(
        secret=secret,
        url=str(data.get("url") or "") if isinstance(data, dict) else "",
        recovery_codes=[str(c) for c in codes] if isinstance(codes, list) else [],
    )


def verify_totp(
    api: CasdoorApi,
    *,
    access_token: str,
    secret: str,
    code: str,
    recovery_code: str,
    cancel: CancelToken | None = None,
) -> None:
    op = "verify_totp"
    required(op, access_token=access_token, secret=secret, code=code, recovery_code=recovery_code)
    owner, name = _token_user(op, access_token)
    api.call(
        op,
        "/api/mfa/setup/verify",
        form={"owner": owner, "name": name, "mfaType": _TOTP, "passcode": code, "secret": secret},
        bearer=access_token,
        cancel=cancel,
    )
    api.call(
        op,
        "/api/mfa/setup/enable",
        form={
            "owner": owner,
            "name": name,
            "mfaType": _TOTP,
            "secret": secret,
            "recoveryCodes": recovery_code,
        },
        bearer=access_token,
        cancel=cancel,
    )
