// Owned by this repository.
//! Sign-in against a real Casdoor (skipped unless GROW_CASDOOR_IT_URL and the GROW_CASDOOR_IT_*
//! application/user variables are set; the TypeScript, Go and Python suites create that state
//! with the admin operations).

use grow_casdoor as sdk;

fn env(name: &str) -> Option<String> {
    std::env::var(format!("GROW_CASDOOR_IT_{name}")).ok()
}

#[tokio::test]
async fn real_casdoor_sign_in() {
    let (Some(url), Some(user), Some(password)) = (env("URL"), env("USER"), env("PASSWORD")) else {
        eprintln!("skipped: GROW_CASDOOR_IT_URL/USER/PASSWORD not set");
        return;
    };
    let cfg = sdk::CasdoorConfig::builder()
        .url(url)
        .client_id(env("CLIENT_ID").unwrap_or_default())
        .client_secret(env("CLIENT_SECRET").unwrap_or_default())
        .organization(env("ORG").unwrap_or_default())
        .application(env("APP").unwrap_or_default())
        .redirect_uri(env("REDIRECT").unwrap_or_default())
        .build()
        .unwrap();
    let c = sdk::CasdoorClient::new(cfg).unwrap();
    assert!(c.health().await.unwrap().healthy);
    c.ping().await.unwrap();
    let t = c
        .sign_in(sdk::SignInInput {
            username: user,
            password: password.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let t2 = c
        .refresh(t.refresh_token.as_deref().unwrap())
        .await
        .unwrap();
    assert_ne!(t2.access_token, t.access_token);
    c.sign_out(&t2.access_token).await.unwrap();
    c.sign_out(&t2.access_token).await.unwrap();
}
