"""Casdoor client against the fake Casdoor: config, core calls, user flows, admin, errors."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

import grow_casdoor as sdk
from _support import MockServer, Reply, closed_port_url, fast_retry
from fake_casdoor import ADMIN_PASSWORD, FakeCasdoor
from grow_casdoor.api import CookieJar
from grow_casdoor.casdoor_errors import envelope_error, masked_object_error, oauth_error
from grow_casdoor.pkce import decode_jwt_payload, user_name_for


@pytest.fixture
def fake() -> Iterator[FakeCasdoor]:
    f = FakeCasdoor()
    yield f
    f.close()


def make(url: str, **kw: Any) -> sdk.CasdoorClient:
    values: dict[str, Any] = {
        "url": url,
        "public_url": "https://auth.example.test/",
        "client_id": "cid",
        "client_secret": "csecret",
        "organization": "acme",
        "application": "app-acme",
        "redirect_uri": "https://app.test/cb",
        "retry": fast_retry(),
    }
    values.update(kw)
    return sdk.CasdoorClient(sdk.CasdoorConfig(**values))


def add_user(fake: FakeCasdoor, name: str, **extra: Any) -> None:
    fake.users[f"acme/{name}"] = {
        "owner": "acme",
        "name": name,
        "email": f"{name}@acme.test",
        "password": "Password-123",
        "emailVerified": True,
        **extra,
    }


# --------------------------------------------------------------------------- config


def test_config_defaults_and_env() -> None:
    c = sdk.CasdoorConfig()
    assert c.url == sdk.DEFAULT_URL
    assert c.public_url == c.url
    assert c.scope == "openid profile email"
    assert (c.admin_username, c.admin_organization, c.admin_application) == (
        "admin",
        "built-in",
        "app-built-in",
    )
    assert c.require_verified_email is True
    env = {
        "GROW_AUTH_ISSUER": "http://casdoor:8000",
        "GROW_AUTH_PUBLIC_URL": "https://auth.example.test/",
        "GROW_AUTH_CLIENT_ID": "client-1",
        "GROW_AUTH_CLIENT_SECRET": "secret-1",
        "GROW_AUTH_ORG": "acme",
        "GROW_AUTH_APP": "app-acme",
        "GROW_AUTH_REDIRECT_URL": "https://app.test/cb",
        "CASDOOR_ADMIN_PASSWORD": "adm1n-pass",
        "GROW_CASDOOR_ORG": "override",
        "GROW_CASDOOR_SCOPE": "openid",
        "GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL": "no",
    }
    c = sdk.CasdoorConfig.from_env(env, application="explicit")
    assert c.url == "http://casdoor:8000"
    assert c.public_url == "https://auth.example.test"
    assert c.client_id == "client-1"
    assert c.client_secret is not None and c.client_secret.reveal() == "secret-1"
    assert c.admin_password is not None and c.admin_password.reveal() == "adm1n-pass"
    assert (c.organization, c.application, c.scope) == ("override", "explicit", "openid")
    assert c.redirect_uri == "https://app.test/cb"
    assert c.require_verified_email is False
    text = repr(c) + str(c)
    assert "secret-1" not in text and "adm1n-pass" not in text
    assert sorted(c.known_secrets()) == ["adm1n-pass", "secret-1"]
    assert (
        sdk.CasdoorConfig.from_env({"GROW_AUTH_PUBLIC_URL": "https://a.test"}).url
        == "https://a.test"
    )


def test_config_validation() -> None:
    with pytest.raises(sdk.ConfigError):
        sdk.CasdoorConfig(client_secret=" ").validate()  # type: ignore[arg-type]
    with pytest.raises(sdk.ConfigError):
        sdk.CasdoorConfig(admin_password=" ").validate()  # type: ignore[arg-type]
    with pytest.raises(sdk.ConfigError):
        sdk.CasdoorConfig(public_url="ftp://x").validate()


# --------------------------------------------------------------------------- core


def test_health_ping_version(fake: FakeCasdoor) -> None:
    with make(fake.url) as c:
        assert c.health().healthy
        assert c.ping() >= 0
        with pytest.raises(sdk.PermissionDeniedError):
            c.server_version()
    with make(fake.url, admin_password=ADMIN_PASSWORD) as c:
        assert c.server_version() == "v4.27.1"
        assert c.ping() >= 0
    with make(fake.url, client_secret="wrong") as c, pytest.raises(sdk.AuthenticationError):
        c.ping()
    with make(fake.url, admin_password="wrong-pass") as c, pytest.raises(sdk.AuthenticationError):
        c.server_version()
    with make(closed_port_url()) as c:
        h = c.health()
        assert (h.healthy, h.status) == (False, "unreachable")
    with make(fake.url, client_secret=None) as c, pytest.raises(sdk.ConfigError):
        c.ping()


def test_health_unhealthy_and_version_missing(server: MockServer) -> None:
    server.defaults["/api/health"] = Reply(200, {"status": "error", "msg": "db"})
    server.defaults["/api/get-version-info"] = Reply(200, {"status": "ok", "data": {}})
    server.defaults["/api/login"] = Reply(
        200, {"status": "ok"}, {"Set-Cookie": "casdoor_session_id=x"}
    )
    with make(server.url, admin_password="pw-123456") as c:
        assert c.health().status == "error"
        with pytest.raises(sdk.UnsupportedError):
            c.server_version()
    server.defaults["/api/health"] = Reply(200, b"not json")
    with make(server.url) as c:
        assert c.health().healthy is False


def test_admin_relogin_and_missing_cookie(server: MockServer) -> None:
    server.defaults["/api/login"] = Reply(
        200, {"status": "ok"}, {"Set-Cookie": "casdoor_session_id=s1"}
    )
    server.replies["/api/get-version-info"].extend(
        [
            Reply(200, {"status": "error", "msg": "Please login first"}),
            Reply(200, {"status": "ok", "data": {"version": "v1"}}),
        ]
    )
    with make(server.url, admin_password="pw-123456") as c:
        assert c.server_version() == "v1"
    assert sum(1 for s in server.seen if s.path.startswith("/api/login")) == 2
    server.defaults["/api/login"] = Reply(200, {"status": "ok"})
    with make(server.url, admin_password="pw-123456") as c, pytest.raises(sdk.ConfigError):
        c.server_version()


def test_closed_client(fake: FakeCasdoor) -> None:
    c = make(fake.url)
    c.close()
    c.close()
    with pytest.raises(sdk.CancelledError):
        c.sign_in(username="a", password="b")
    with pytest.raises(sdk.CancelledError):
        c.build_authorize_url(redirect_uri="r", state="s", code_challenge="c")
    assert "CasdoorClient(" in repr(make(fake.url))


# --------------------------------------------------------------------------- user flows


def test_sign_up_verify_sign_in(fake: FakeCasdoor) -> None:
    with make(fake.url) as c:
        r = c.sign_up(email="new.user@acme.test", password="Password-123", display_name="New")
        assert r == sdk.SignUpResult(user_id="acme/new-user", organization="acme", name="new-user")
        with pytest.raises(sdk.EmailNotVerifiedError):
            c.sign_in(username="new.user@acme.test", password="Password-123")
        c.send_email_verification("new.user@acme.test")
        code = fake.mails["new.user@acme.test"]
        with pytest.raises(sdk.AuthenticationError):
            c.verify_email(email="new.user@acme.test", code="000000")
        c.verify_email(email="new.user@acme.test", code=code)
        c.verify_email(email="new.user@acme.test", code=code)
        assert fake.users["acme/new-user"]["emailVerified"] is True
        t = c.sign_in(username="new.user@acme.test", password="Password-123")
        assert t.refresh_token and t.expires_at is not None and t.token_type == "Bearer"
        assert "ey" not in repr(t)
        assert (decode_jwt_payload(t.access_token) or {})["name"] == "new-user"


def test_sign_up_with_code_and_fallback_id(fake: FakeCasdoor, server: MockServer) -> None:
    with make(fake.url, require_verified_email=False) as c:
        c.send_email_verification("code.user@acme.test", purpose="signup")
        r = c.sign_up(
            username="code_user",
            email="code.user@acme.test",
            password="Password-123",
            email_code=fake.mails["code.user@acme.test"],
        )
        assert r.user_id == "acme/code_user"
    server.defaults["/api/signup"] = Reply(200, {"status": "ok", "data": "Affected"})
    with make(server.url, organization="o") as c:
        assert c.sign_up(email="x@y.z", password="p").user_id == "o/x"


def test_wrong_password_and_input_validation(fake: FakeCasdoor) -> None:
    add_user(fake, "alice")
    with make(fake.url) as c:
        with pytest.raises(sdk.AuthenticationError) as info:
            c.sign_in(username="alice", password="nope")
        assert sdk.casdoor_reason(info.value) == sdk.CasdoorReason.INVALID_CREDENTIALS
        assert info.value.casdoor_code == "wrong-password"  # type: ignore[attr-defined]
        for call in (
            lambda: c.sign_in(username="alice", password=""),
            lambda: c.sign_up(email="a@b.c", password=" "),
            lambda: c.refresh(""),
            lambda: c.sign_out(""),
            lambda: c.reset_password(email="a@b.c", code="1", new_password=""),
            lambda: c.send_email_verification("a@b.c", purpose="other"),
        ):
            with pytest.raises(sdk.ValidationError):
                call()
    with make(fake.url, redirect_uri=None) as c, pytest.raises(sdk.ConfigError):
        c.sign_in(username="a", password="b")
    with (
        make(fake.url, organization=None) as c,
        pytest.raises(sdk.ConfigError, match="organization"),
    ):
        c.sign_up(email="a@b.c", password="p")
    with make(fake.url, application=None) as c, pytest.raises(sdk.ConfigError, match="application"):
        c.sign_up(email="a@b.c", password="p")
    with make(fake.url, client_id=None) as c, pytest.raises(sdk.ConfigError, match="client_id"):
        c.sign_in(username="a", password="b")


def test_refresh_and_sign_out(fake: FakeCasdoor, server: MockServer) -> None:
    add_user(fake, "bob")
    with make(fake.url) as c:
        t = c.sign_in(username="bob", password="Password-123", redirect_uri="https://app.test/cb")
        t2 = c.refresh(t.refresh_token or "")
        assert t2.access_token != t.access_token
        with pytest.raises(sdk.AuthenticationError):
            c.refresh(t.refresh_token or "")
        c.sign_out(t2.access_token)
        c.sign_out(t2.access_token)
    server.defaults["/api/logout"] = Reply(
        200, {"status": "error", "msg": "Unauthorized operation"}
    )
    server.defaults["/api/login"] = Reply(200, {"status": "ok", "data": None})
    server.defaults["/api/login/oauth/refresh_token"] = Reply(200, {"token_type": "Bearer"})
    with make(server.url) as c:
        with pytest.raises(sdk.PermissionDeniedError):
            c.sign_out("t")
        with pytest.raises(sdk.ValidationError, match="no authorization code"):
            c.sign_in(username="a", password="b")
        with pytest.raises(sdk.ValidationError, match="no access_token"):
            c.refresh("rt")


def test_oauth_errors_in_bodies(server: MockServer) -> None:
    server.defaults["/api/login/oauth/refresh_token"] = Reply(
        200, {"error": "invalid_grant", "error_description": "x"}
    )
    server.defaults["/api/login/oauth/access_token"] = Reply(
        200, {"status": "error", "msg": "Please login first"}
    )
    server.defaults["/api/get-application"] = Reply(
        403, {"status": "error", "msg": "Unauthorized operation"}
    )
    with make(server.url) as c:
        with pytest.raises(sdk.AuthenticationError):
            c.refresh("rt")
        with pytest.raises(sdk.AuthenticationError):
            c.exchange_code(code="c", code_verifier="v", redirect_uri="r")
        with pytest.raises(sdk.PermissionDeniedError):
            c.ping()
    server.defaults["/api/login/oauth/refresh_token"] = Reply(
        500, {"status": "error", "msg": "Please login first"}
    )
    server.defaults["/api/get-application"] = Reply(400, {"x": 1})
    with make(server.url) as c:
        with pytest.raises(sdk.AuthenticationError):
            c.refresh("rt")
        with pytest.raises(sdk.ValidationError):
            c.ping()
    server.defaults["/api/login/oauth/refresh_token"] = Reply(400, {"error": "invalid_client"})
    with make(server.url) as c, pytest.raises(sdk.AuthenticationError):
        c.refresh("rt")


def test_authorize_url_and_code_exchange(fake: FakeCasdoor) -> None:
    import httpx

    add_user(fake, "carol")
    with make(fake.url) as c:
        pkce = sdk.create_pkce()
        assert pkce.code_challenge == sdk.pkce_challenge(pkce.code_verifier)
        url = urlsplit(
            c.build_authorize_url(
                redirect_uri="https://app.test/cb",
                state=sdk.random_state(),
                code_challenge=pkce.code_challenge,
                nonce="n1",
                extra={"prompt": "login"},
            )
        )
        q = parse_qs(url.query)
        assert (
            f"{url.scheme}://{url.netloc}{url.path}"
            == "https://auth.example.test/login/oauth/authorize"
        )
        assert (
            q["client_id"] == ["cid"]
            and q["code_challenge_method"] == ["S256"]
            and q["prompt"] == ["login"]
        )
        with pytest.raises(sdk.ValidationError):
            c.build_authorize_url(redirect_uri="", state="s", code_challenge="x")

        def browser_code() -> str:
            r = httpx.post(
                f"{fake.url}/api/login",
                params={"clientId": "cid", "code_challenge": pkce.code_challenge},
                json={"organization": "acme", "username": "carol", "password": "Password-123"},
            )
            return str(r.json()["data"])

        with pytest.raises(sdk.AuthenticationError):
            c.exchange_code(
                code=browser_code(), code_verifier="wrong", redirect_uri="https://app.test/cb"
            )
        t = c.exchange_code(
            code=browser_code(),
            code_verifier=pkce.code_verifier,
            redirect_uri="https://app.test/cb",
        )
        assert "." in t.access_token
    with (
        make(fake.url, client_secret="wrong-secret") as c,
        pytest.raises(sdk.AuthenticationError) as info,
    ):
        c.exchange_code(code="x", code_verifier="y", redirect_uri="z")
    assert sdk.casdoor_reason(info.value) == sdk.CasdoorReason.INVALID_CLIENT


def test_email_codes_and_password_reset(fake: FakeCasdoor) -> None:
    add_user(fake, "dave")
    add_user(fake, "dup")
    with make(fake.url) as c:
        c.send_email_verification("fresh@acme.test")
        with pytest.raises(sdk.RateLimitError) as info:
            c.send_email_verification("fresh@acme.test")
        assert info.value.retry_after == 60
        with pytest.raises(sdk.NotFoundError):
            c.send_email_verification("other@acme.test", purpose="verify")
        with pytest.raises(sdk.ConflictError):
            c.send_email_verification("dup@acme.test", purpose="signup")
        c.send_email_verification("ghost@acme.test", purpose="signup")
        with pytest.raises(sdk.ValidationError, match="email_code"):
            c.verify_email(email="ghost@acme.test", code=fake.mails["ghost@acme.test"])
        c.forgot_password("dave@acme.test")
        code = fake.mails["dave@acme.test"]
        with pytest.raises(sdk.AuthenticationError):
            c.reset_password(email="dave@acme.test", code="999999", new_password="New-Password-456")
        c.reset_password(email="dave@acme.test", code=code, new_password="New-Password-456")
        with pytest.raises(sdk.AuthenticationError):
            c.sign_in(username="dave", password="Password-123")
        assert c.sign_in(username="dave", password="New-Password-456").access_token
        with pytest.raises(sdk.NotFoundError):
            c.forgot_password("nobody@acme.test")
        with pytest.raises(sdk.NotFoundError):
            c.reset_password(email="nobody@acme.test", code=code, new_password="x-123456789")


def test_totp(fake: FakeCasdoor, server: MockServer) -> None:
    add_user(fake, "erin")
    with make(fake.url) as c:
        t = c.sign_in(username="erin", password="Password-123")
        with pytest.raises(sdk.PermissionDeniedError, match="not allowed by the MFA items"):
            c.setup_totp(t.access_token)
        fake.orgs["admin/acme"]["mfaItems"] = [{"name": "app", "rule": "Optional"}]
        s = c.setup_totp(t.access_token)
        assert s.recovery_codes == ["rc-1"]
        assert s.secret not in repr(s)
        with pytest.raises(sdk.ValidationError):
            c.verify_totp(
                access_token=t.access_token, secret=s.secret, code="000000", recovery_code="rc-1"
            )
        assert "totpSecret" not in fake.users["acme/erin"]
        c.verify_totp(
            access_token=t.access_token,
            secret=s.secret,
            code=sdk.totp_code(s.secret),
            recovery_code="rc-1",
        )
        with pytest.raises(sdk.MfaRequiredError) as info:
            c.sign_in(username="erin", password="Password-123")
        assert info.value.mfa_types == ["app"]
        assert sdk.casdoor_reason(info.value) == sdk.CasdoorReason.MFA_REQUIRED
        assert c.sign_in(
            username="erin", password="Password-123", totp_code=sdk.totp_code(s.secret)
        ).access_token
        assert c.sign_in(
            username="erin", password="Password-123", recovery_code="rc-1"
        ).access_token
        with pytest.raises(sdk.AuthenticationError):
            c.sign_in(username="erin", password="Password-123", totp_code="000000")
        with pytest.raises(sdk.ValidationError, match="owner/name"):
            c.setup_totp("opaque-token")
    server.defaults["/api/mfa/setup/initiate"] = Reply(200, {"status": "ok", "data": {}})
    with make(server.url) as c, pytest.raises(sdk.ValidationError, match="no TOTP secret"):
        c.setup_totp(t.access_token)


# --------------------------------------------------------------------------- admin


def test_admin_setup_is_idempotent(fake: FakeCasdoor) -> None:
    kw: dict[str, Any] = {
        "admin_password": ADMIN_PASSWORD,
        "organization": "shop",
        "application": "app-shop",
        "client_id": "shop-client",
        "client_secret": "shop-secret-0123456789",
    }
    with make(fake.url, **kw) as c:
        assert c.ensure_organization("shop", display_name="Shop") == ("shop", True)
        assert c.ensure_organization("shop", display_name="Shop") == ("shop", False)
        c.ensure_organization("shop", enable_totp=False, password_options=["AtLeast12"])
        assert fake.orgs["admin/shop"]["passwordOptions"] == ["AtLeast12"]
        app = c.ensure_application(
            redirect_uris=["https://shop.test/cb"], providers=["provider-mail"]
        )
        assert (app.client_id, app.client_secret, app.created) == (
            "shop-client",
            "shop-secret-0123456789",
            True,
        )
        assert "shop-secret" not in repr(app)
        again = c.ensure_application(
            redirect_uris=["https://shop.test/cb", "https://b.test/cb"], sign_up_email_code=True
        )
        assert again.created is False and again.redirect_uris == [
            "https://shop.test/cb",
            "https://b.test/cb",
        ]
        stored = fake.apps["admin/app-shop"]
        assert (
            stored["tokenFormat"] == "JWT"
            and stored["enablePassword"] is True
            and len(stored["providers"]) == 1
        )
        smtp = sdk.SmtpSettings(
            name="provider-mail",
            host="mailpit",
            port=1025,
            from_address="no-reply@shop.test",
            disable_ssl=True,
        )
        assert c.ensure_email_provider(smtp) == ("provider-mail", True)
        smtp2 = sdk.SmtpSettings(
            name="provider-mail",
            host="mailpit2",
            port=1025,
            from_address="no-reply@shop.test",
            password="smtp-pw",
        )
        assert c.ensure_email_provider(smtp2) == ("provider-mail", False)
        assert fake.providers["admin/provider-mail"]["host"] == "mailpit2"
        assert fake.providers["admin/provider-mail"]["clientId2"] == "no-reply@shop.test"
        c.ensure_email_provider(
            sdk.SmtpSettings(name="provider-2", host="h", port=25, from_address="a@b.c")
        )
        assert [p["name"] for p in fake.apps["admin/app-shop"]["providers"]] == [
            "provider-mail",
            "provider-2",
        ]
        with pytest.raises(sdk.ValidationError):
            c.ensure_email_provider(sdk.SmtpSettings(host="h", port=0, from_address="a@b.c"))
        assert c.ensure_roles(["buyer", "seller"]) == [
            sdk.RoleInfo("buyer", True),
            sdk.RoleInfo("seller", True),
        ]
        assert c.ensure_roles(["buyer"])[0].created is False
        with pytest.raises(sdk.ValidationError):
            c.ensure_roles([""])
        u = c.ensure_user(email="buyer@shop.test", password="Password-123", roles=["buyer"])
        assert (u.user_id, u.email_verified, u.created) == ("shop/buyer", True, True)
        assert fake.roles["shop/buyer"]["users"] == ["shop/buyer"]
        u2 = c.ensure_user(
            email="buyer@shop.test",
            password="Password-456",
            display_name="B",
            roles=["buyer", "admin"],
        )
        assert u2.created is False and u2.display_name == "B"
        assert fake.users["shop/buyer"]["password"] == "Password-456"
        assert fake.roles["shop/admin"]["users"] == ["shop/buyer"]
        assert c.ensure_user(email="buyer@shop.test").created is False
        c.assign_roles("buyer@shop.test", ["seller"])
        c.assign_roles("shop/buyer", ["seller"])
        assert fake.roles["shop/seller"]["users"] == ["shop/buyer"]
        with pytest.raises(sdk.NotFoundError):
            c.assign_roles("nobody", ["seller"])


def test_admin_with_client_credentials_and_generated_secrets(fake: FakeCasdoor) -> None:
    with make(fake.url) as c:
        assert (
            c.ensure_application(redirect_uris=["https://app.test/cb"]).client_secret == "csecret"
        )
    assert "/api/login" not in fake.calls
    with make(fake.url, admin_password=ADMIN_PASSWORD, client_id=None, client_secret=None) as c:
        app = c.ensure_application(name="app-new", organization="shop")
        assert len(app.client_id) == 20 and len(app.client_secret) == 40


def test_admin_masked_and_not_created(server: MockServer) -> None:
    server.defaults["/api/login"] = Reply(
        200, {"status": "ok"}, {"Set-Cookie": "casdoor_session_id=x"}
    )
    server.defaults["/api/get-application"] = Reply(
        200,
        {
            "status": "ok",
            "data": {
                "owner": "admin",
                "name": "a",
                "clientSecret": "***",
                "cert": "***",
                "samlReplyUrl": "***",
            },
        },
    )
    with make(server.url, admin_password="pw-123456", organization="o", application="a") as c:
        with pytest.raises(sdk.PermissionDeniedError) as info:
            c.ensure_application(redirect_uris=["x"])
        assert sdk.casdoor_reason(info.value) == sdk.CasdoorReason.MASKED_OBJECT
    server.defaults["/api/get-application"] = Reply(200, {"status": "ok", "data": None})
    server.defaults["/api/get-user"] = Reply(200, {"status": "ok", "data": None})
    server.defaults["/api/get-organization"] = Reply(200, {"status": "ok", "data": None})
    with make(server.url, admin_password="pw-123456", organization="o", application="a") as c:
        with pytest.raises(sdk.ValidationError, match="was not created"):
            c.ensure_application()
        with pytest.raises(sdk.ValidationError, match="was not created"):
            c.ensure_user(email="a@b.c", password="Password-1")
        with pytest.raises(sdk.ValidationError, match="password is required"):
            c.ensure_user(email="a@b.c")
        assert c.ensure_organization("o") == ("o", True)


# --------------------------------------------------------------------------- errors + helpers


@pytest.mark.parametrize(
    ("msg", "cls", "reason"),
    [
        ("Phone number is invalid in your region US", sdk.ValidationError, "empty_credential"),
        (
            "password or code is incorrect, you have 4 remaining chances",
            sdk.AuthenticationError,
            "invalid_credentials",
        ),
        ("Please login first", sdk.AuthenticationError, "login_required"),
        ("Unauthorized operation", sdk.PermissionDeniedError, "forbidden"),
        (
            "wrong password or code too many times, please wait for 15 minutes",
            sdk.RateLimitError,
            "locked",
        ),
        ("the account is frozen", sdk.PermissionDeniedError, "locked"),
        ("you can only send one code in 60s", sdk.RateLimitError, "rate_limited"),
        (
            'pq: duplicate key value violates unique constraint "x"',
            sdk.ConflictError,
            "already_exists",
        ),
        ("The user: acme/x doesn't exist", sdk.NotFoundError, "not_found"),
        ("The login method: login with email is not enabled", sdk.UnsupportedError, "not_enabled"),
        ("something else", sdk.ValidationError, "other"),
    ],
)
def test_envelope_error_mapping(msg: str, cls: type[Exception], reason: str) -> None:
    err = envelope_error("op", msg, "c1")
    assert isinstance(err, cls)
    assert sdk.casdoor_reason(err) == reason
    assert err.message.startswith("op: ")


def test_error_details() -> None:
    assert (
        "empty password"
        in envelope_error("op", "Phone number is invalid in your region US").message
    )
    locked = envelope_error("op", "too many times, please wait for 15 minutes")
    assert locked.retry_after == 900 and locked.retryable is False
    assert "status error" in envelope_error("op", "").message
    assert len(envelope_error("op", "x" * 400).message) < 320
    assert sdk.casdoor_reason(ValueError()) is None
    assert isinstance(oauth_error("t", "invalid_grant", "bad", 400), sdk.AuthenticationError)
    assert (
        sdk.casdoor_reason(oauth_error("t", "invalid_grant", "the account is frozen", 400))
        == "locked"
    )
    assert isinstance(oauth_error("t", "unsupported_grant_type", "", 400), sdk.UnsupportedError)
    assert isinstance(oauth_error("t", "invalid_request", "", 400), sdk.ValidationError)
    assert isinstance(
        oauth_error("t", "invalid_grant", "the user has MFA enabled", 400), sdk.MfaRequiredError
    )
    assert isinstance(masked_object_error("op", "application"), sdk.PermissionDeniedError)


def test_helpers() -> None:
    assert sdk.totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59) == "287082"
    with pytest.raises(ValueError, match="base32"):
        sdk.totp_code("!!!")
    assert decode_jwt_payload("abc") is None
    assert decode_jwt_payload("a.!!!.c") is None
    assert decode_jwt_payload("a.MQ.c") is None
    assert user_name_for("john.doe@x.test") == "john-doe"
    assert user_name_for("x@y", "valid_name") == "valid_name"
    assert user_name_for("@y") == "user"
    jar = CookieJar()
    assert jar.header() is None
    jar.absorb(object())
    t = sdk.TokenSet.from_response({"access_token": "a", "expires_in": 0, "scope": "openid"})
    assert (t.expires_in, t.scope) == (None, "openid")


def test_async_client(fake: FakeCasdoor) -> None:
    add_user(fake, "zed")

    async def main() -> None:
        cfg = make(fake.url).config
        async with sdk.AsyncCasdoorClient(cfg) as c:
            assert (await c.health()).healthy
            t = await c.sign_in(username="zed", password="Password-123")
            assert (await c.refresh(t.refresh_token)).access_token
            assert c.build_authorize_url(
                redirect_uri="r", state="s", code_challenge="c"
            ).startswith("https://")
            assert "AsyncCasdoorClient(" in repr(c)
            assert c.resources is not None

    asyncio.run(main())
    assert isinstance(
        sdk.AsyncCasdoorClient.from_env({"GROW_CASDOOR_URL": fake.url}), sdk.AsyncCasdoorClient
    )
    assert sdk.CasdoorClient.from_env({"GROW_CASDOOR_URL": fake.url}).resources is not None
