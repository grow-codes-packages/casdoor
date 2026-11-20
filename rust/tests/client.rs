// Owned by this repository: the Rust skeleton client against wiremock.
//! Config (platform env names) and the Casdoor skeleton flows against a mock Casdoor.

mod common;

use common::{closed_port, fast_retry};
use grow_casdoor as sdk;
use sdk::core::{EnvReader, ErrorCode};
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use sdk::CasdoorClient as Client;
use sdk::CasdoorConfig as Config;

fn jwt(payload: serde_json::Value) -> String {
    let b = serde_json::to_vec(&payload).unwrap();
    format!("e30.{}.sig", sdk::casdoor::base64_url(&b))
}

fn client(url: &str) -> Client {
    let cfg = Config::builder()
        .url(url)
        .retry(fast_retry(0.0))
        .public_url("https://auth.example.test/")
        .client_id("cid")
        .client_secret("csecret")
        .organization("acme")
        .application("app-acme")
        .redirect_uri("https://app.test/cb")
        .build()
        .unwrap();
    Client::new(cfg).unwrap()
}

#[test]
fn config_reads_platform_names() {
    let env = EnvReader::from_map([
        ("GROW_AUTH_ISSUER", "http://casdoor:8000"),
        ("GROW_AUTH_PUBLIC_URL", "https://auth.example.test/"),
        ("GROW_AUTH_CLIENT_ID", "client-1"),
        ("GROW_AUTH_CLIENT_SECRET", "secret-1"),
        ("GROW_AUTH_ORG", "acme"),
        ("GROW_AUTH_APP", "app-acme"),
        ("GROW_AUTH_REDIRECT_URL", "https://app.test/cb"),
        ("CASDOOR_ADMIN_PASSWORD", "adm1n-pass"),
        ("GROW_CASDOOR_ORG", "override"),
        ("GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL", "false"),
    ]);
    let c = Config::builder().build_with_env(&env).unwrap();
    assert_eq!(c.url().as_str(), "http://casdoor:8000/");
    assert_eq!(c.public_url(), "https://auth.example.test");
    assert_eq!(c.client_id(), Some("client-1"));
    assert_eq!(c.client_secret().unwrap().expose_secret(), "secret-1");
    assert_eq!(c.organization(), Some("override"));
    assert_eq!(c.application(), Some("app-acme"));
    assert_eq!(c.redirect_uri(), Some("https://app.test/cb"));
    assert_eq!(c.admin_password().unwrap().expose_secret(), "adm1n-pass");
    assert_eq!(c.scope(), sdk::DEFAULT_SCOPE);
    assert!(c.allow_unverified_email());
    let dbg = format!("{c:?}");
    assert!(!dbg.contains("secret-1") && !dbg.contains("adm1n-pass"));
    assert_eq!(
        Config::builder()
            .client_secret(" ")
            .build()
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
    assert_eq!(
        Config::builder()
            .public_url("ftp://x")
            .build()
            .unwrap_err()
            .code(),
        ErrorCode::Config
    );
}

#[tokio::test]
async fn health_ping_and_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/api/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status":"ok"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/get-application"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"status":"error","msg":"Please login first"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/get-version-info"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"status":"error","msg":"Unauthorized operation"})),
        )
        .mount(&server)
        .await;
    let c = client(&server.uri());
    assert!(c.health().await.unwrap().healthy);
    assert_eq!(
        c.ping().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    assert_eq!(
        c.server_version().await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    let down = client(&format!("http://127.0.0.1:{}", closed_port()));
    assert!(!down.health().await.unwrap().healthy);
    c.close().await;
    assert!(c.is_closed());
    assert_eq!(
        c.build_authorize_url("r", "s", "c").unwrap_err().code(),
        ErrorCode::Cancelled
    );
}

#[tokio::test]
async fn sign_in_refresh_sign_out() {
    let server = MockServer::start().await;
    let access = jwt(json!({"owner":"acme","name":"alice","email_verified":true}));
    Mock::given(method("POST"))
        .and(path("/api/login"))
        .and(query_param("code_challenge_method", "S256"))
        .and(body_string_contains("\"password\":\"Password-123\""))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"status":"ok","data":"code-1"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status":"error","code":"wrong-password","msg":"password or code is incorrect, you have 4 remaining chances"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/login/oauth/access_token"))
        .and(body_string_contains("code_verifier="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":access,"refresh_token":"rt-1","token_type":"Bearer","expires_in":3600})))
        .mount(&server)
        .await;
    Mock::given(path("/api/login/oauth/refresh_token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error":"invalid_grant","error_description":"refresh token is invalid or revoked"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/logout"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"status":"error","msg":"Access token has expired"})),
        )
        .mount(&server)
        .await;
    let c = client(&server.uri());
    let t = c
        .sign_in(sdk::SignInInput {
            username: "alice".into(),
            password: "Password-123".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(t.refresh_token.as_deref(), Some("rt-1"));
    assert!(t.expires_at.is_some());
    assert!(!format!("{t:?}").contains("rt-1"));
    let wrong = c
        .sign_in(sdk::SignInInput {
            username: "alice".into(),
            password: "nope".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), ErrorCode::Authentication);
    let empty = c
        .sign_in(sdk::SignInInput {
            username: "alice".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(empty.code(), ErrorCode::Validation);
    assert_eq!(
        c.refresh("rt-1").await.unwrap_err().code(),
        ErrorCode::Authentication
    );
    c.sign_out(&t.access_token).await.unwrap();
    assert_eq!(
        c.exchange_code("code-1", "v", "https://app.test/cb")
            .await
            .unwrap()
            .access_token,
        access
    );
    let url = c
        .build_authorize_url("https://app.test/cb", "st", "ch")
        .unwrap();
    assert!(url.starts_with("https://auth.example.test/login/oauth/authorize?client_id=cid"));
    assert!(url.contains("code_challenge_method=S256"));
}

#[tokio::test]
async fn mfa_and_unverified_email() {
    let server = MockServer::start().await;
    Mock::given(path("/api/login"))
        .and(body_string_contains("passcode"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"status":"ok","data":"code-2"})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/login"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"status":"ok","data":"NextMfa","data2":[{"mfaType":"app"}]})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/login/oauth/access_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": jwt(json!({"email_verified": false}))})),
        )
        .mount(&server)
        .await;
    let c = client(&server.uri());
    let mfa = c
        .sign_in(sdk::SignInInput {
            username: "erin".into(),
            password: "Password-123".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(mfa.message().contains("mfa_required"));
    let unverified = c
        .sign_in(sdk::SignInInput {
            username: "erin".into(),
            password: "Password-123".into(),
            totp_code: Some("123456".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(unverified.code(), ErrorCode::PermissionDenied);
}

#[test]
fn helpers() {
    let p = sdk::Pkce::new();
    assert_eq!(p.code_challenge, sdk::pkce_challenge(&p.code_verifier));
    assert_eq!(p.code_verifier.len(), 64);
    assert_ne!(sdk::random_state(), sdk::random_state());
    // RFC 7636 appendix B
    assert_eq!(
        sdk::pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert_eq!(sdk::casdoor::base64_std(b"cid:secret"), "Y2lkOnNlY3JldA==");
    assert!(sdk::casdoor::payload("x").is_none());
    for (msg, code) in [
        (
            "Phone number is invalid in your region US",
            ErrorCode::Validation,
        ),
        ("you can only send one code in 60s", ErrorCode::RateLimited),
        ("Unauthorized operation", ErrorCode::PermissionDenied),
        ("duplicate key", ErrorCode::Conflict),
        ("The user doesn't exist", ErrorCode::NotFound),
        ("The login method is not enabled", ErrorCode::Unsupported),
        ("", ErrorCode::Validation),
    ] {
        assert_eq!(
            sdk::casdoor::envelope_error("op", msg).code(),
            code,
            "{msg}"
        );
    }
    assert_eq!(
        sdk::casdoor::oauth_error("t", "unsupported_grant_type", "", 400).code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        sdk::casdoor::oauth_error("t", "invalid_request", "", 400).code(),
        ErrorCode::Validation
    );
}
