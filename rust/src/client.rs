// Skeleton created by sdk-kit 0.3.0; owned by this repository (edit freely).
//! `CasdoorClient`: entry point of the SDK (SPEC §2.4) with the Casdoor user flows of the Rust
//! skeleton: sign-in (code + PKCE), code exchange, refresh, sign-out and the authorize URL.
//! The admin operations and the e-mail/password/TOTP flows exist in TypeScript, Go and Python
//! (see `docs/compatibility.md`).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use futures::future::BoxFuture;
use serde_json::{json, Value};

use crate::casdoor::{
    envelope_error, form_body, oauth_error, payload, random_state, required, Pkce, TokenSet,
};
use crate::config::CasdoorConfig;
use crate::core::lifecycle::CloseGroup;
use crate::core::{Error, ErrorCode, HealthStatus, HttpTransport, Result, Secret};

/// Async client for Casdoor. Cheap to clone (clones share one connection pool).
#[derive(Debug, Clone)]
pub struct CasdoorClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: CasdoorConfig,
    transport: HttpTransport,
    on_close: CloseGroup,
}

/// Input of [`CasdoorClient::sign_in`].
#[derive(Debug, Clone, Default)]
pub struct SignInInput {
    /// User name or e-mail.
    pub username: String,
    /// Password.
    pub password: Secret,
    /// Current TOTP code when the user has MFA.
    pub totp_code: Option<String>,
    /// Redirect URI registered on the application (default: config `redirect_uri`).
    pub redirect_uri: Option<String>,
}

impl CasdoorClient {
    /// Creates a client from a configuration.
    pub fn new(config: CasdoorConfig) -> Result<Self> {
        config.validate()?;
        let transport = HttpTransport::new(config.common())?;
        for secret in [config.client_secret(), config.admin_password()]
            .into_iter()
            .flatten()
        {
            transport.add_known_secret(secret);
        }
        Ok(CasdoorClient {
            inner: Arc::new(Inner {
                config,
                transport,
                on_close: CloseGroup::new(),
            }),
        })
    }

    /// Creates a client from the process environment (`GROW_CASDOOR_*`, then
    /// `GROW_AUTH_ISSUER|PUBLIC_URL`, `GROW_AUTH_CLIENT_ID/SECRET`, `GROW_AUTH_ORG/APP`, …).
    pub fn from_env() -> Result<Self> {
        Self::new(CasdoorConfig::from_env()?)
    }

    /// The configuration in use.
    pub fn config(&self) -> &CasdoorConfig {
        &self.inner.config
    }

    /// The HTTP transport (for service modules).
    pub fn transport(&self) -> &HttpTransport {
        &self.inner.transport
    }

    /// Registers work that [`CasdoorClient::close`] runs.
    pub fn on_close<F>(&self, f: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static,
    {
        self.inner.on_close.register(f);
    }

    /// `GET /api/health`. Never fails for an unhealthy or unreachable service.
    pub async fn health(&self) -> Result<HealthStatus> {
        let resp = self
            .transport()
            .get("/api/health")
            .operation("health")
            .ok_status(500)
            .ok_status(503)
            .send()
            .await;
        let resp = match resp {
            Ok(resp) => resp,
            Err(err) => return HealthStatus::from_error(err),
        };
        let word = resp
            .json::<Value>()
            .ok()
            .and_then(|b| b.get("status").and_then(Value::as_str).map(str::to_owned));
        Ok(match word.as_deref() {
            Some("ok") if resp.status() < 300 => HealthStatus::healthy("ok"),
            _ => HealthStatus::unhealthy(word.unwrap_or_else(|| "unhealthy".to_owned()))
                .with_detail("httpStatus", resp.status().to_string()),
        })
    }

    /// Authenticated round trip with the client credentials; returns the latency.
    pub async fn ping(&self) -> Result<Duration> {
        let started = Instant::now();
        let app = self.config().application().unwrap_or("app-built-in");
        let req = self
            .transport()
            .get("/api/get-application")
            .query("id", format!("admin/{app}"))
            .operation("ping");
        let req = match (self.config().client_id(), self.config().client_secret()) {
            (Some(id), Some(secret)) => req.secret_header(
                "authorization",
                &Secret::new(format!(
                    "Basic {}",
                    crate::casdoor::base64_std(
                        format!("{id}:{}", secret.expose_secret()).as_bytes()
                    )
                )),
            ),
            // Without client credentials: Casdoor answers application reads anonymously (masked).
            _ => req,
        };
        let resp = req.send().await?;
        self.envelope("ping", &resp)?;
        Ok(started.elapsed())
    }

    /// Server version (`/api/get-version-info`); needs an admin session, so the Rust
    /// skeleton reports `UNSUPPORTED` unless Casdoor answers anonymously.
    pub async fn server_version(&self) -> Result<String> {
        let resp = self
            .transport()
            .get("/api/get-version-info")
            .operation("serverVersion")
            .send()
            .await?;
        let env = self.envelope("serverVersion", &resp).map_err(|e| {
            if e.code() == ErrorCode::PermissionDenied {
                Error::unsupported(
                    "serverVersion: needs the admin session (not in the Rust skeleton)",
                )
            } else {
                e
            }
        })?;
        env.pointer("/data/version")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| Error::unsupported("serverVersion: the service exposes no version"))
    }

    fn envelope(&self, op: &str, resp: &crate::core::Response) -> Result<Value> {
        let body: Value = resp.json().unwrap_or(Value::Null);
        if body.get("status").and_then(Value::as_str) == Some("error") {
            let msg = body.get("msg").and_then(Value::as_str).unwrap_or("");
            return Err(envelope_error(op, &self.transport().redact(msg)));
        }
        Ok(body)
    }

    fn need<'a>(&self, op: &str, name: &str, v: Option<&'a str>) -> Result<&'a str> {
        v.ok_or_else(|| Error::config(format!("{op}: {name} is not configured")))
    }

    /// Headless password sign-in: `/api/login` (code + PKCE) then the token endpoint.
    /// `AUTHENTICATION` with "a second factor is required" when the user has TOTP and no code was
    /// given; `PERMISSION_DENIED` when the e-mail is not verified (unless allowed).
    pub async fn sign_in(&self, input: SignInInput) -> Result<TokenSet> {
        let op = "signIn";
        required(op, "username", &input.username)?;
        required(op, "password", input.password.expose_secret())?;
        let cfg = self.config();
        let redirect = match input.redirect_uri.as_deref().or(cfg.redirect_uri()) {
            Some(r) => r.to_owned(),
            None => {
                return Err(Error::config(format!(
                    "{op}: redirect_uri is not configured"
                )))
            }
        };
        let client_id = self.need(op, "client_id", cfg.client_id())?;
        let app = self.need(op, "application", cfg.application())?;
        let org = self.need(op, "organization", cfg.organization())?;
        let pkce = Pkce::new();
        let body = json!({
            "application": app, "organization": org, "username": input.username,
            "password": input.password.expose_secret(), "type": "code",
            "signinMethod": "Password", "autoSignin": false,
        });
        let state = random_state();
        let login = |body: Value, cookie: Option<String>| {
            let mut req = self
                .transport()
                .post("/api/login")
                .query("clientId", client_id)
                .query("responseType", "code")
                .query("redirectUri", redirect.clone())
                .query("scope", cfg.scope())
                .query("state", state.clone())
                .query("code_challenge", pkce.code_challenge.clone())
                .query("code_challenge_method", "S256")
                .operation(op)
                .json(&body);
            if let Some(c) = cookie {
                req = req.secret_header("cookie", &Secret::new(c));
            }
            req.send()
        };
        let resp = login(body, None).await?;
        let mut env = self.envelope(op, &resp)?;
        if env.get("data").and_then(Value::as_str) == Some("NextMfa") {
            let Some(code) = input.totp_code.filter(|c| !c.is_empty()) else {
                return Err(Error::new(
                    ErrorCode::Authentication,
                    format!("{op}: a second factor is required (mfa_required)"),
                ));
            };
            // Same Casdoor session; the second step sends only the passcode.
            let cookie = resp
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .filter_map(|v| v.split(';').next())
                .collect::<Vec<_>>()
                .join("; ");
            let second = json!({
                "application": app, "organization": org, "type": "code",
                "passcode": code, "mfaType": "app",
            });
            let resp2 = login(second, Some(cookie)).await?;
            env = self.envelope(op, &resp2)?;
        }
        match env.get("data").and_then(Value::as_str) {
            Some(code) if !code.is_empty() && code != "NextMfa" => {
                let t = self
                    .exchange(op, code, &pkce.code_verifier, &redirect)
                    .await?;
                self.check_verified(op, t)
            }
            _ => Err(Error::validation(format!(
                "{op}: Casdoor returned no authorization code"
            ))),
        }
    }

    fn check_verified(&self, op: &str, t: TokenSet) -> Result<TokenSet> {
        if self.config().allow_unverified_email() {
            return Ok(t);
        }
        if payload(&t.access_token).and_then(|p| p.get("email_verified").cloned())
            == Some(Value::Bool(false))
        {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                format!("{op}: the e-mail address is not verified (email_not_verified)"),
            ));
        }
        Ok(t)
    }

    async fn oauth(&self, op: &str, path: &str, form: &[(&str, &str)]) -> Result<Value> {
        let resp = self
            .transport()
            .post(path)
            .operation(op)
            .body(form_body(form), "application/x-www-form-urlencoded")
            .map_error(|e| {
                let body: Value = e.json().unwrap_or(Value::Null);
                body.get("error").and_then(Value::as_str).map(|code| {
                    oauth_error(
                        e.operation,
                        code,
                        body.get("error_description")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                        e.status,
                    )
                })
            })
            .send()
            .await?;
        let body: Value = resp.json()?;
        if let Some(code) = body.get("error").and_then(Value::as_str) {
            let desc = body
                .get("error_description")
                .and_then(Value::as_str)
                .unwrap_or("");
            return Err(oauth_error(
                op,
                code,
                &self.transport().redact(desc),
                resp.status(),
            ));
        }
        if body.get("status").and_then(Value::as_str) == Some("error") {
            let msg = body.get("msg").and_then(Value::as_str).unwrap_or("");
            return Err(envelope_error(op, &self.transport().redact(msg)));
        }
        Ok(body)
    }

    async fn exchange(
        &self,
        op: &str,
        code: &str,
        verifier: &str,
        redirect: &str,
    ) -> Result<TokenSet> {
        let cfg = self.config();
        let client_id = self.need(op, "client_id", cfg.client_id())?;
        let secret = cfg
            .client_secret()
            .map(|s| s.expose_secret().to_owned())
            .unwrap_or_default();
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
            ("client_id", client_id),
        ];
        if !secret.is_empty() {
            form.push(("client_secret", &secret));
        }
        TokenSet::from_body(
            op,
            &self
                .oauth(op, "/api/login/oauth/access_token", &form)
                .await?,
            SystemTime::now(),
        )
    }

    /// Exchanges the authorization code of the browser redirect for tokens.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenSet> {
        let op = "exchangeCode";
        required(op, "code", code)?;
        required(op, "code_verifier", code_verifier)?;
        required(op, "redirect_uri", redirect_uri)?;
        let t = self.exchange(op, code, code_verifier, redirect_uri).await?;
        self.check_verified(op, t)
    }

    /// New tokens from a refresh token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenSet> {
        let op = "refresh";
        required(op, "refresh_token", refresh_token)?;
        let cfg = self.config();
        let client_id = self.need(op, "client_id", cfg.client_id())?;
        let secret = cfg
            .client_secret()
            .map(|s| s.expose_secret().to_owned())
            .unwrap_or_default();
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("scope", cfg.scope()),
        ];
        if !secret.is_empty() {
            form.push(("client_secret", &secret));
        }
        TokenSet::from_body(
            op,
            &self
                .oauth(op, "/api/login/oauth/refresh_token", &form)
                .await?,
            SystemTime::now(),
        )
    }

    /// Ends the Casdoor session of the token (`/api/logout`). Idempotent.
    pub async fn sign_out(&self, token: &str) -> Result<()> {
        let op = "signOut";
        required(op, "token", token)?;
        let result = self
            .transport()
            .post("/api/logout")
            .query("id_token_hint", token)
            .operation(op)
            .ok_status(401)
            .send()
            .await;
        let resp = result?;
        if resp.status() == 401 {
            return Ok(());
        }
        match self.envelope(op, &resp) {
            Err(e) if e.code() == ErrorCode::Authentication => Ok(()),
            other => other.map(|_| ()),
        }
    }

    /// Browser authorize URL on `public_url` (code flow, PKCE S256).
    pub fn build_authorize_url(
        &self,
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> Result<String> {
        let op = "buildAuthorizeUrl";
        self.transport().ensure_open(op)?;
        required(op, "redirect_uri", redirect_uri)?;
        required(op, "state", state)?;
        required(op, "code_challenge", code_challenge)?;
        let cfg = self.config();
        let client_id = self.need(op, "client_id", cfg.client_id())?;
        let query = form_body(&[
            ("client_id", client_id),
            ("response_type", "code"),
            ("redirect_uri", redirect_uri),
            ("scope", cfg.scope()),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ]);
        Ok(format!(
            "{}/login/oauth/authorize?{query}",
            cfg.public_url()
        ))
    }

    /// Flushes and stops background work, then closes the transport. Idempotent.
    pub async fn close(&self) {
        self.inner.on_close.close().await;
        self.inner.transport.close();
    }

    /// Whether [`CasdoorClient::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.inner.transport.is_closed()
    }
}
