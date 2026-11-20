"""A stateful fake Casdoor (threaded HTTP server) reproducing the quirks the client handles:
HTTP 200 + ``{"status":"error"}``, "Phone number is invalid" for empty passwords, masked
``***`` secrets for non-admins, full-object updates, cookie sessions, PKCE, NextMfa and one
verification code per address per 60 s."""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from grow_casdoor import totp_code

ADMIN_PASSWORD = "admin-pass-123"
Obj = dict[str, Any]


def _b64(obj: Obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class FakeCasdoor:
    """Organization ``acme`` with application ``app-acme`` (client ``cid``/``csecret``)."""

    def __init__(self) -> None:
        self.orgs: dict[str, Obj] = {
            "admin/acme": {"owner": "admin", "name": "acme", "mfaItems": []}
        }
        self.apps: dict[str, Obj] = {
            "admin/app-acme": {
                "owner": "admin",
                "name": "app-acme",
                "organization": "acme",
                "clientId": "cid",
                "clientSecret": "csecret",
                "cert": "cert-built-in",
                "redirectUris": ["https://app.test/cb"],
                "providers": [],
            }
        }
        self.providers: dict[str, Obj] = {}
        self.roles: dict[str, Obj] = {}
        self.users: dict[str, Obj] = {}
        self.mails: dict[str, str] = {}
        self.calls: list[str] = []
        self._mail_times: dict[str, float] = {}
        self._sessions: dict[str, Obj] = {}
        self._access: dict[str, str] = {}
        self._refresh: dict[str, str] = {}
        self._codes: dict[str, Obj] = {}
        self._seq = itertools.count(1)
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def _do(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                with fake._lock:
                    status, payload, headers = fake.handle(
                        self.command, self.path, dict(self.headers), body
                    )
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            do_GET = _do
            do_POST = _do

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    # ------------------------------------------------------------------ helpers

    def _next(self, prefix: str) -> str:
        return f"{prefix}{next(self._seq)}"

    def _issue(self, user_id: str) -> Obj:
        u = self.users.get(user_id, {})
        roles = [{"name": r["name"]} for r in self.roles.values() if user_id in r.get("users", [])]
        payload = {
            "owner": u.get("owner"),
            "name": u.get("name"),
            "email": u.get("email"),
            "email_verified": u.get("emailVerified") is True,
            "roles": roles,
        }
        access = f"{_b64({'alg': 'RS256'})}.{_b64(payload)}.{self._next('sig')}"
        refresh = self._next("rt")
        self._access[access] = user_id
        self._refresh[refresh] = user_id
        return {
            "access_token": access,
            "refresh_token": refresh,
            "id_token": access,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid",
        }

    def _find_user(self, owner: str, key: str) -> Obj | None:
        for u in self.users.values():
            if u.get("owner") == owner and key in (u.get("name"), u.get("email")):
                return u
        return None

    @staticmethod
    def ok(data: Any = None, data2: Any = None) -> tuple[int, Any]:
        return 200, {"status": "ok", "msg": "", "data": data, "data2": data2}

    @staticmethod
    def fail(msg: str, code: str | None = None) -> tuple[int, Any]:
        body: Obj = {"status": "error", "msg": msg, "data": None}
        if code:
            body["code"] = code
        return 200, body

    # ------------------------------------------------------------------ routing

    def handle(
        self, method: str, raw_path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, Any, dict[str, str]]:
        parts = urlsplit(raw_path)
        path = parts.path
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        self.calls.append(path)
        cookie = headers.get("Cookie", "")
        m = re.search(r"casdoor_session_id=([^;]+)", cookie)
        extra: dict[str, str] = {}
        if m and m.group(1) in self._sessions:
            sess = self._sessions[m.group(1)]
        else:
            sid = self._next("sess")
            sess = self._sessions.setdefault(sid, {})
            extra["Set-Cookie"] = f"casdoor_session_id={sid}; Path=/; HttpOnly"
        status, payload = self.route(path, q, headers, body, sess)
        return status, payload, extra

    def _who(self, headers: dict[str, str], sess: Obj) -> str | None:
        auth = headers.get("Authorization", "")
        if auth.startswith("Basic "):
            cid, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
            ok = any(
                a["clientId"] == cid and a["clientSecret"] == secret for a in self.apps.values()
            )
            return "app" if ok else "bad"
        if auth.startswith("Bearer "):
            return self._access.get(auth[7:], "expired")
        user = sess.get("user")
        return user if isinstance(user, str) else None

    def route(
        self, path: str, q: dict[str, str], headers: dict[str, str], raw: bytes, sess: Obj
    ) -> tuple[int, Any]:
        who = self._who(headers, sess)
        admin = who in ("admin", "app")
        if who == "bad":
            return self.fail("Please login first")
        if who == "expired":
            return 401, {"status": "error", "msg": "Access token has expired"}
        form = (
            {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            if raw and not raw.startswith(b"{")
            else {}
        )
        body: Obj = json.loads(raw) if raw.startswith(b"{") else {}

        if path == "/api/health":
            return self.ok()
        if path == "/api/get-version-info":
            return (
                self.ok({"version": "v4.27.1"})
                if who == "admin"
                else self.fail("Unauthorized operation")
            )
        if path == "/api/login":
            return self._login(q, body, sess)
        if path == "/api/login/oauth/access_token":
            app = next(
                (a for a in self.apps.values() if a["clientId"] == form.get("client_id")), None
            )
            if app is None or app["clientSecret"] != form.get("client_secret"):
                return 400, {
                    "error": "invalid_client",
                    "error_description": "client_secret is invalid",
                }
            entry = self._codes.pop(form.get("code", ""), None)
            if entry is None:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "authorization code is invalid",
                }
            digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
            if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != entry["challenge"]:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "code_verifier is invalid",
                }
            return 200, self._issue(entry["user"])
        if path == "/api/login/oauth/refresh_token":
            user_id = self._refresh.pop(form.get("refresh_token", ""), None)
            if user_id is None:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "refresh token is invalid or revoked",
                }
            return 200, self._issue(user_id)
        if path == "/api/logout":
            token = q.get("id_token_hint", "")
            if token not in self._access:
                return 401, {"status": "error", "msg": "Access token has expired"}
            del self._access[token]
            return self.ok()
        if path == "/api/signup":
            return self._signup(body)
        if path == "/api/send-verification-code":
            return self._send_code(form)
        if path == "/api/verify-code":
            if not body.get("code"):
                return self.fail("Phone number is invalid in your region US")
            if self.mails.get(str(body.get("username"))) != body.get("code"):
                return self.fail("password or code is incorrect, you have 4 remaining chances")
            sess["verifiedCode"] = body["code"]
            return self.ok()
        if path == "/api/set-password":
            if not form.get("code") or sess.get("verifiedCode") != form.get("code"):
                return self.fail("Please login first")
            user = self.users.get(f"{form.get('userOwner')}/{form.get('userName')}")
            if user is None:
                return self.fail("The user doesn't exist")
            user["password"] = form.get("newPassword")
            return self.ok()
        if path.startswith("/api/mfa/setup/"):
            return self._mfa(path, form, who)
        m = re.match(r"^/api/(get|add|update)-(organization|application|provider|role|user)$", path)
        if m:
            return self._crud(m.group(1), m.group(2), q, body, admin)
        return 404, b"not found"

    def _code(self, q: dict[str, str], user: Obj) -> tuple[int, Any]:
        code = self._next("code")
        self._codes[code] = {
            "user": f"{user['owner']}/{user['name']}",
            "challenge": q.get("code_challenge"),
        }
        return self.ok(code)

    def _login(self, q: dict[str, str], body: Obj, sess: Obj) -> tuple[int, Any]:
        if "password" not in body and isinstance(sess.get("mfaUser"), str):
            user = self.users[sess["mfaUser"]]
            pass_ok = body.get("passcode") is not None and body.get("passcode") == totp_code(
                user["totpSecret"]
            )
            rec_ok = body.get("recoveryCode") is not None and body.get("recoveryCode") == user.get(
                "recoveryCode"
            )
            if not pass_ok and not rec_ok:
                return self.fail(
                    "totp passcode error, password or code is incorrect, you have 4 remaining"
                    " chances",
                    "mfa-failed",
                )
            del sess["mfaUser"]
            return self._code(q, user)
        if not body.get("password"):
            return self.fail("Phone number is invalid in your region US")
        if "clientId" not in q:
            if body.get("username") == "admin" and body.get("password") == ADMIN_PASSWORD:
                sess["user"] = "admin"
                return self.ok("built-in/admin")
            return self.fail(
                "password or code is incorrect, you have 4 remaining chances", "wrong-password"
            )
        user = self._find_user(str(body.get("organization")), str(body.get("username")))
        if user is None:
            return self.fail(f"The user: acme/{body.get('username')} doesn't exist")
        if user.get("password") != body.get("password"):
            return self.fail(
                "password or code is incorrect, you have 4 remaining chances", "wrong-password"
            )
        if user.get("totpSecret"):
            sess["mfaUser"] = f"{user['owner']}/{user['name']}"  # a passcode here is ignored
            return self.ok("NextMfa", [{"enabled": True, "mfaType": "app"}])
        return self._code(q, user)

    def _signup(self, body: Obj) -> tuple[int, Any]:
        if body.get("password") == "":
            return self.fail("Phone number is invalid in your region US")
        app = self.apps.get(f"admin/{body.get('application')}", {})
        needs_code = any(
            i.get("name") == "Email" and i.get("rule") == "Normal"
            for i in app.get("signupItems", [])
        )
        if self._find_user(str(body.get("organization")), str(body.get("username"))):
            return self.fail("The username already exists")
        if needs_code and body.get("emailCode") != self.mails.get(str(body.get("email"))):
            return self.fail("password or code is incorrect, you have 4 remaining chances")
        uid = f"{body['organization']}/{body['username']}"
        self.users[uid] = {
            "owner": body["organization"],
            "name": body["username"],
            "email": body.get("email"),
            "password": body.get("password"),
            "displayName": body.get("displayName"),
            "emailVerified": needs_code,
        }
        return self.ok(uid)

    def _send_code(self, form: dict[str, str]) -> tuple[int, Any]:
        dest = form.get("dest", "")
        last = self._mail_times.get(dest)
        if last is not None and time.time() - last < 60:
            return self.fail("you can only send one code in 60s")
        owner = str(self.apps.get(form.get("applicationId", ""), {}).get("organization", ""))
        user = self._find_user(owner, dest)
        method = form.get("method")
        if method in ("login", "forget") and user is None:
            return self.fail("the user does not exist, please sign up first")
        if method == "signup" and user is not None:
            return self.fail("Email already exists")
        if method == "forget" and self._find_user(owner, form.get("checkUser", "")) is None:
            return self.fail("the user does not exist, please sign up first")
        self.mails[dest] = str(100000 + next(self._seq))
        self._mail_times[dest] = time.time()
        return self.ok()

    def _mfa(self, path: str, form: dict[str, str], who: str | None) -> tuple[int, Any]:
        uid = f"{form.get('owner')}/{form.get('name')}"
        if who != uid:
            return self.fail("Unauthorized operation")
        user = self.users[uid]
        org = self.orgs.get(f"admin/{user['owner']}", {})
        if not any(i.get("name") == "app" for i in org.get("mfaItems", [])):
            return self.fail("the MFA type: app is not allowed by the MFA items")
        if path.endswith("/initiate"):
            return self.ok(
                {
                    "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                    "url": "otpauth://totp/x",
                    "recoveryCodes": ["rc-1"],
                }
            )
        if not form.get("secret"):
            return self.fail("totp secret is missing")
        if path.endswith("/verify"):
            return (
                self.ok("OK")
                if form.get("passcode") == totp_code(form["secret"])
                else self.fail("passcode is invalid")
            )
        user["totpSecret"] = form["secret"]
        user["recoveryCode"] = form.get("recoveryCodes")
        return self.ok("OK")

    def _crud(
        self, verb: str, kind: str, q: dict[str, str], body: Obj, admin: bool
    ) -> tuple[int, Any]:
        store = {
            "organization": self.orgs,
            "application": self.apps,
            "provider": self.providers,
            "role": self.roles,
            "user": self.users,
        }[kind]
        if verb == "get":
            if kind in ("application", "organization"):
                obj = store.get(q.get("id", ""))
                if obj is None:
                    return self.ok(None)
                return self.ok(obj if admin else {**obj, "clientSecret": "***", "cert": "***"})
            if not admin:
                return self.fail("Please login first")
            if kind == "user" and "email" in q:
                u = self._find_user(q.get("owner", ""), q["email"])
                return self.ok(None if u is None else {**u, "password": "***"})
            obj = store.get(q.get("id", ""))
            if obj is None:
                return self.ok(None)
            return self.ok({**obj, "password": "***"} if kind == "user" else obj)
        if not admin:
            return self.fail("Please login first")
        if verb == "add":
            oid = f"{body.get('owner')}/{body.get('name')}"
            if oid in store:
                return self.fail('pq: duplicate key value violates unique constraint "pkey"')
            store[oid] = dict(body)
            return self.ok("Affected")
        oid = q.get("id", "")
        cur = store.get(oid)
        if cur is None:
            return self.fail(f"The {kind}: {oid} does not exist")
        nxt = dict(body)  # full-object update
        if kind == "user" and body.get("password") == "***":
            nxt["password"] = cur.get("password")
        store[oid] = nxt
        return self.ok("Affected")
