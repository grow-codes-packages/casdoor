"""Every admin operation and user flow against the Docker Casdoor + Mailpit (settings from
/bootstrap/env; same test as tests/test_real_casdoor.py).

Env: GROW_CASDOOR_IT_URL, GROW_CASDOOR_IT_ADMIN_PASSWORD, GROW_CASDOOR_IT_MAILPIT (Mailpit HTTP
URL seen from the test), GROW_CASDOOR_IT_SMTP_HOST (Mailpit SMTP host seen from Casdoor).
"""

from __future__ import annotations

import re
import secrets
import time
from datetime import datetime

import httpx
import pytest

import grow_casdoor as sdk
from conftest import load_env
from grow_casdoor.pkce import decode_jwt_payload

_ENV = load_env()
URL = _ENV.get("GROW_CASDOOR_IT_URL")
MAILPIT = _ENV.get("GROW_CASDOOR_IT_MAILPIT", "")

pytestmark = pytest.mark.skipif(URL is None, reason="GROW_CASDOOR_IT_URL is not set")


def mail_code(to: str, since: float) -> str:
    for _ in range(60):
        found = httpx.get(f"{MAILPIT}/api/v1/search", params={"query": f"to:{to}"}).json()
        for msg in found.get("messages") or []:
            created = datetime.fromisoformat(msg["Created"].replace("Z", "+00:00")).timestamp()
            if created >= since - 2:
                text = httpx.get(f"{MAILPIT}/api/v1/message/{msg['ID']}").json()["Text"]
                m = re.search(r"\b(\d{6})\b", text)
                if m:
                    return m.group(1)
        time.sleep(0.5)
    raise AssertionError(f"no mail for {to}")


def test_real_casdoor_flows() -> None:
    rid = secrets.token_hex(3)
    org, app, redirect = f"itpy-{rid}", f"app-itpy-{rid}", "https://app.test/auth/callback"
    common = {
        "url": URL,
        "organization": org,
        "application": app,
        "client_id": f"cid-{rid}",
        "client_secret": secrets.token_hex(20),
        "redirect_uri": redirect,
    }
    buyer = f"buyer-{rid}@example.test"
    with sdk.CasdoorClient(
        sdk.CasdoorConfig(admin_password=_ENV.get("GROW_CASDOOR_IT_ADMIN_PASSWORD"), **common)
    ) as admin:
        assert admin.health().healthy
        assert admin.server_version().startswith("v")
        assert admin.ensure_organization(org) == (org, True)
        assert admin.ensure_organization(org) == (org, False)
        info = admin.ensure_application(redirect_uris=[redirect])
        assert info.created and info.client_secret == common["client_secret"]
        assert not admin.ensure_application(redirect_uris=[redirect]).created
        admin.ensure_email_provider(
            sdk.SmtpSettings(
                name=f"provider-mail-{rid}",
                host=_ENV.get("GROW_CASDOOR_IT_SMTP_HOST", "mailpit"),
                port=1025,
                from_address=f"no-reply@{org}.test",
                disable_ssl=True,
            )
        )
        assert all(r.created for r in admin.ensure_roles(["buyer", "seller"]))
        assert admin.ensure_user(email=buyer, password="Password-123", roles=["buyer"]).created
        assert not admin.ensure_user(email=buyer, password="Password-456").created
        admin.assign_roles(buyer, ["seller"])
        assert admin.ping() >= 0

    with sdk.CasdoorClient(sdk.CasdoorConfig(**common)) as c:
        with pytest.raises(sdk.AuthenticationError):
            c.sign_in(username=buyer, password="Password-123")
        t = c.sign_in(username=buyer, password="Password-456")
        claims = decode_jwt_payload(t.access_token) or {}
        assert sorted(r["name"] for r in claims["roles"]) == ["buyer", "seller"]
        t2 = c.refresh(t.refresh_token or "")
        assert t2.access_token != t.access_token
        c.sign_out(t2.access_token)
        c.sign_out(t2.access_token)

        new = f"new-{rid}@example.test"
        assert c.sign_up(email=new, password="Password-123").user_id == f"{org}/new-{rid}"
        with pytest.raises(sdk.EmailNotVerifiedError):
            c.sign_in(username=new, password="Password-123")
        since = time.time()
        c.send_email_verification(new)
        c.verify_email(email=new, code=mail_code(new, since))
        assert c.sign_in(username=new, password="Password-123").access_token

        since = time.time()
        c.forgot_password(buyer)
        c.reset_password(email=buyer, code=mail_code(buyer, since), new_password="Password-789")
        t3 = c.sign_in(username=buyer, password="Password-789")

        s = c.setup_totp(t3.access_token)
        c.verify_totp(
            access_token=t3.access_token,
            secret=s.secret,
            code=sdk.totp_code(s.secret),
            recovery_code=s.recovery_codes[0],
        )
        with pytest.raises(sdk.MfaRequiredError):
            c.sign_in(username=buyer, password="Password-789")
        assert c.sign_in(
            username=buyer, password="Password-789", totp_code=sdk.totp_code(s.secret)
        ).access_token

        pkce = sdk.create_pkce()
        assert "/login/oauth/authorize?" in c.build_authorize_url(
            redirect_uri=redirect, state=sdk.random_state(), code_challenge=pkce.code_challenge
        )
        r = httpx.post(
            f"{URL}/api/login",
            params={
                "clientId": common["client_id"],
                "responseType": "code",
                "redirectUri": redirect,
                "scope": "openid",
                "state": "s",
                "code_challenge": pkce.code_challenge,
                "code_challenge_method": "S256",
            },
            json={
                "application": app,
                "organization": org,
                "username": new,
                "password": "Password-123",
                "type": "code",
            },
        )
        code = r.json()["data"]
        assert c.exchange_code(
            code=code, code_verifier=pkce.code_verifier, redirect_uri=redirect
        ).access_token
