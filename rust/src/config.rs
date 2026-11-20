// Skeleton created by sdk-kit 0.3.0; owned by this repository (edit freely).
//! `CasdoorConfig`: common settings (SPEC §2.2) plus the Casdoor credentials.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::core::{
    CommonConfig, CommonConfigBuilder, EnvReader, Hooks, Result, RetryPolicy, Secret, TlsConfig,
    VendorEnv,
};

/// Endpoint used when neither the builder nor the environment sets one.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8000";

/// Default OAuth scope.
pub const DEFAULT_SCOPE: &str = "openid profile email";

/// Platform variables checked (in order) after the matching `GROW_CASDOOR_*` variable.
const VENDOR_ENV: VendorEnv<'static> = VendorEnv {
    url: &["GROW_AUTH_ISSUER", "GROW_AUTH_PUBLIC_URL", "CASDOOR_URL"],
    ..VendorEnv::NONE
};

/// Immutable client configuration; build it with [`CasdoorConfig::builder`] or
/// [`CasdoorConfig::from_env`]. `Debug` output redacts every credential.
#[derive(Debug, Clone)]
pub struct CasdoorConfig {
    common: CommonConfig,
    s: Settings,
}

/// Casdoor settings (all optional; see the builder methods).
#[derive(Debug, Clone, Default)]
struct Settings {
    public_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<Secret>,
    organization: Option<String>,
    application: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    admin_password: Option<Secret>,
    allow_unverified_email: bool,
}

impl CasdoorConfig {
    /// A builder with nothing set.
    pub fn builder() -> CasdoorConfigBuilder {
        CasdoorConfigBuilder::default()
    }

    /// Configuration from the process environment
    /// (explicit > `GROW_CASDOOR_*` > vendor variables > defaults).
    pub fn from_env() -> Result<Self> {
        Self::builder().build_from_env()
    }

    /// Settings shared by every Grow Codes SDK.
    pub fn common(&self) -> &CommonConfig {
        &self.common
    }

    /// Endpoint base URL.
    pub fn url(&self) -> &url::Url {
        self.common.url()
    }

    /// Browser-facing URL (`GROW_CASDOOR_PUBLIC_URL`, `GROW_AUTH_PUBLIC_URL`; default `url`).
    pub fn public_url(&self) -> String {
        self.s
            .public_url
            .clone()
            .unwrap_or_else(|| self.url().as_str().to_owned())
            .trim_end_matches('/')
            .to_owned()
    }
    /// OAuth client id (`GROW_CASDOOR_CLIENT_ID`, `GROW_AUTH_CLIENT_ID`).
    pub fn client_id(&self) -> Option<&str> {
        self.s.client_id.as_deref()
    }
    /// OAuth client secret (`GROW_CASDOOR_CLIENT_SECRET`, `GROW_AUTH_CLIENT_SECRET`).
    pub fn client_secret(&self) -> Option<&Secret> {
        self.s.client_secret.as_ref()
    }
    /// Casdoor organization (`GROW_CASDOOR_ORG`, `GROW_AUTH_ORG`).
    pub fn organization(&self) -> Option<&str> {
        self.s.organization.as_deref()
    }
    /// Casdoor application (`GROW_CASDOOR_APP`, `GROW_AUTH_APP`).
    pub fn application(&self) -> Option<&str> {
        self.s.application.as_deref()
    }
    /// Default redirect URI (`GROW_CASDOOR_REDIRECT_URL`, `GROW_AUTH_REDIRECT_URL`).
    pub fn redirect_uri(&self) -> Option<&str> {
        self.s.redirect_uri.as_deref()
    }
    /// OAuth scope (`GROW_CASDOOR_SCOPE`, default [`DEFAULT_SCOPE`]).
    pub fn scope(&self) -> &str {
        self.s.scope.as_deref().unwrap_or(DEFAULT_SCOPE)
    }
    /// Built-in admin password (`GROW_CASDOOR_ADMIN_PASSWORD`, `CASDOOR_ADMIN_PASSWORD`).
    pub fn admin_password(&self) -> Option<&Secret> {
        self.s.admin_password.as_ref()
    }
    /// Whether tokens of unverified e-mail addresses are accepted
    /// (`GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL=false`).
    pub fn allow_unverified_email(&self) -> bool {
        self.s.allow_unverified_email
    }

    /// Checks the service rules (common rules are checked when building).
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("client_secret", &self.s.client_secret),
            ("admin_password", &self.s.admin_password),
        ] {
            if value
                .as_ref()
                .is_some_and(|v| v.expose_secret().trim().is_empty())
            {
                return Err(crate::core::Error::config(format!(
                    "invalid configuration: {name} must not be blank"
                )));
            }
        }
        let public = self.public_url();
        if !(public.starts_with("http://") || public.starts_with("https://")) {
            return Err(crate::core::Error::config(
                "invalid configuration: public_url must be an http(s) URL",
            ));
        }
        Ok(())
    }
}

/// Builder for [`CasdoorConfig`]. Values set here win over the environment.
#[derive(Debug, Clone, Default)]
pub struct CasdoorConfigBuilder {
    common: CommonConfigBuilder,
    s: Settings,
}

impl CasdoorConfigBuilder {
    /// Endpoint base URL (default [`DEFAULT_URL`]).
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.common = self.common.url(url);
        self
    }
    /// Browser-facing URL for the authorize URL.
    pub fn public_url(mut self, v: impl Into<String>) -> Self {
        self.s.public_url = Some(v.into());
        self
    }
    /// OAuth client id.
    pub fn client_id(mut self, v: impl Into<String>) -> Self {
        self.s.client_id = Some(v.into());
        self
    }
    /// OAuth client secret.
    pub fn client_secret(mut self, v: impl Into<Secret>) -> Self {
        self.s.client_secret = Some(v.into());
        self
    }
    /// Casdoor organization.
    pub fn organization(mut self, v: impl Into<String>) -> Self {
        self.s.organization = Some(v.into());
        self
    }
    /// Casdoor application.
    pub fn application(mut self, v: impl Into<String>) -> Self {
        self.s.application = Some(v.into());
        self
    }
    /// Default redirect URI of the code flow.
    pub fn redirect_uri(mut self, v: impl Into<String>) -> Self {
        self.s.redirect_uri = Some(v.into());
        self
    }
    /// OAuth scope.
    pub fn scope(mut self, v: impl Into<String>) -> Self {
        self.s.scope = Some(v.into());
        self
    }
    /// Built-in admin password.
    pub fn admin_password(mut self, v: impl Into<Secret>) -> Self {
        self.s.admin_password = Some(v.into());
        self
    }
    /// Accept tokens of unverified e-mail addresses.
    pub fn allow_unverified_email(mut self, v: bool) -> Self {
        self.s.allow_unverified_email = v;
        self
    }
    /// Connect timeout (default 10 s).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.connect_timeout(timeout);
        self
    }
    /// Per-attempt timeout (default 30 s).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.request_timeout(timeout);
        self
    }
    /// Whole-call timeout including retries (default 120 s).
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.common = self.common.total_timeout(timeout);
        self
    }
    /// Retry policy.
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.common = self.common.retry(retry);
        self
    }
    /// Maximum retries (default 3).
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.common = self.common.max_retries(max_retries);
        self
    }
    /// TLS settings.
    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.common = self.common.tls(tls);
        self
    }
    /// Extra trusted CA certificates (PEM file).
    pub fn ca_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.common = self.common.ca_cert_path(path);
        self
    }
    /// Disables TLS verification (tests only).
    pub fn insecure_skip_verify(mut self, skip: bool) -> Self {
        self.common = self.common.insecure_skip_verify(skip);
        self
    }
    /// Proxy URL (environment proxies are ignored).
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.common = self.common.proxy(proxy);
        self
    }
    /// Extra request header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.common = self.common.header(name, value);
        self
    }
    /// Text appended to the User-Agent.
    pub fn user_agent_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.common = self.common.user_agent_suffix(suffix);
        self
    }
    /// Request hooks.
    pub fn hooks(mut self, hooks: Arc<dyn Hooks>) -> Self {
        self.common = self.common.hooks(hooks);
        self
    }
    /// Edits any other common setting.
    pub fn common(mut self, f: impl FnOnce(CommonConfigBuilder) -> CommonConfigBuilder) -> Self {
        self.common = f(self.common);
        self
    }

    /// Builds without reading the environment.
    pub fn build(self) -> Result<CasdoorConfig> {
        let config = CasdoorConfig {
            common: self.common.build(DEFAULT_URL)?,
            s: self.s,
        };
        config.validate()?;
        Ok(config)
    }

    /// Fills unset values from the process environment, then builds.
    pub fn build_from_env(self) -> Result<CasdoorConfig> {
        self.build_with_env(&EnvReader::new())
    }

    /// Fills unset values from `env`, then builds.
    pub fn build_with_env(mut self, env: &EnvReader) -> Result<CasdoorConfig> {
        self.common = self.common.apply_env_with(env, &VENDOR_ENV)?;
        let s = &mut self.s;
        for (slot, name, vendor) in [
            (
                &mut s.public_url,
                "PUBLIC_URL",
                &["GROW_AUTH_PUBLIC_URL"][..],
            ),
            (&mut s.client_id, "CLIENT_ID", &["GROW_AUTH_CLIENT_ID"][..]),
            (&mut s.organization, "ORG", &["GROW_AUTH_ORG"][..]),
            (&mut s.application, "APP", &["GROW_AUTH_APP"][..]),
            (
                &mut s.redirect_uri,
                "REDIRECT_URL",
                &["GROW_AUTH_REDIRECT_URL"][..],
            ),
            (&mut s.scope, "SCOPE", &[][..]),
        ] {
            if slot.is_none() {
                *slot = env.string(name, vendor);
            }
        }
        if s.client_secret.is_none() {
            s.client_secret = env.secret("CLIENT_SECRET", &["GROW_AUTH_CLIENT_SECRET"]);
        }
        if s.admin_password.is_none() {
            s.admin_password = env.secret("ADMIN_PASSWORD", &["CASDOOR_ADMIN_PASSWORD"]);
        }
        if !s.allow_unverified_email && env.bool("REQUIRE_VERIFIED_EMAIL", &[])? == Some(false) {
            s.allow_unverified_email = true;
        }
        self.build()
    }
}
