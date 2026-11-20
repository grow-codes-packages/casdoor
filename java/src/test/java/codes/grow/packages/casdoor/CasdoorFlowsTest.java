package codes.grow.packages.casdoor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.casdoor.core.AuthenticationException;
import codes.grow.packages.casdoor.core.CancelledException;
import codes.grow.packages.casdoor.core.ConfigException;
import codes.grow.packages.casdoor.core.ConflictException;
import codes.grow.packages.casdoor.core.EnvReader;
import codes.grow.packages.casdoor.core.MockServer;
import codes.grow.packages.casdoor.core.NotFoundException;
import codes.grow.packages.casdoor.core.PermissionDeniedException;
import codes.grow.packages.casdoor.core.RateLimitException;
import codes.grow.packages.casdoor.core.RetryPolicy;
import codes.grow.packages.casdoor.core.UnsupportedException;
import codes.grow.packages.casdoor.core.ValidationException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CasdoorFlowsTest {
  private MockServer server;

  @BeforeEach
  void start() throws Exception {
    server = MockServer.start();
  }

  @AfterEach
  void stop() {
    server.close();
  }

  private static String jwt(String payload) {
    return "e30."
        + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payload.getBytes(StandardCharsets.UTF_8))
        + ".sig";
  }

  private CasdoorClient client(CasdoorAuthSettings.Builder s) {
    return CasdoorClient.builder()
        .url(server.url())
        .retry(RetryPolicy.builder().maxRetries(0).initialBackoff(Duration.ofMillis(1)).build())
        .settings(s.build())
        .build();
  }

  private static CasdoorAuthSettings.Builder settings() {
    return CasdoorAuthSettings.builder()
        .clientId("cid")
        .clientSecret("csecret")
        .organization("acme")
        .application("app-acme")
        .redirectUri("https://app.test/cb")
        .publicUrl("https://auth.example.test/");
  }

  @Test
  void settingsFromPlatformEnv() {
    EnvReader env =
        EnvReader.of(
            Map.of(
                "GROW_AUTH_ISSUER", "http://casdoor:8000",
                "GROW_AUTH_CLIENT_ID", "client-1",
                "GROW_AUTH_CLIENT_SECRET", "secret-1",
                "GROW_AUTH_ORG", "acme",
                "GROW_AUTH_APP", "app-acme",
                "GROW_AUTH_REDIRECT_URL", "https://app.test/cb",
                "GROW_AUTH_PUBLIC_URL", "https://auth.example.test",
                "GROW_CASDOOR_ORG", "override",
                "GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL", "false"));
    try (CasdoorClient c = CasdoorClient.builder().fromEnv(env).build()) {
      assertThat(c.config().url()).isEqualTo("http://casdoor:8000");
      CasdoorAuthSettings s = c.settings();
      assertThat(s.clientId()).contains("client-1");
      assertThat(s.clientSecret().get().reveal()).isEqualTo("secret-1");
      assertThat(s.organization()).contains("override");
      assertThat(s.application()).contains("app-acme");
      assertThat(s.redirectUri()).contains("https://app.test/cb");
      assertThat(s.publicUrl()).contains("https://auth.example.test");
      assertThat(s.scope()).isEqualTo(CasdoorAuthSettings.DEFAULT_SCOPE);
      assertThat(s.allowUnverifiedEmail()).isTrue();
      assertThat(s.toString()).doesNotContain("secret-1");
    }
    assertThat(CasdoorAuthSettings.empty().clientId()).isEmpty();
    assertThat(CasdoorAuthSettings.builder().scope("openid").build().scope()).isEqualTo("openid");
  }

  @Test
  void signInRefreshSignOut() {
    String access = jwt("{\"owner\":\"acme\",\"name\":\"alice\",\"email_verified\":true}");
    server
        .enqueue(200, "{\"status\":\"ok\",\"data\":\"code-1\"}")
        .enqueue(
            200,
            "{\"access_token\":\""
                + access
                + "\",\"refresh_token\":\"rt-1\",\"token_type\":\"Bearer\",\"expires_in\":3600}")
        .enqueue(
            400, "{\"error\":\"invalid_grant\",\"error_description\":\"refresh token is invalid\"}")
        .enqueue(401, "{\"status\":\"error\",\"msg\":\"Access token has expired\"}")
        .enqueue(200, "{\"status\":\"error\",\"msg\":\"Please login first\"}")
        .enqueue(200, "{\"status\":\"ok\"}");
    try (CasdoorClient c = client(settings())) {
      TokenSet t = c.signIn("alice", "Password-123", null);
      assertThat(t.accessToken()).isEqualTo(access);
      assertThat(t.refreshToken()).contains("rt-1");
      assertThat(t.expiresAt()).isPresent();
      assertThat(t.toString()).doesNotContain("rt-1");
      assertThat(server.requests().get(0).uri()).contains("code_challenge_method=S256");
      assertThat(server.requests().get(1).body()).contains("code_verifier=");
      assertThatThrownBy(() -> c.refresh("rt-1")).isInstanceOf(AuthenticationException.class);
      c.signOut(access);
      c.signOut(access);
      c.signOut(access);
    }
  }

  @Test
  void signInErrors() {
    server
        .enqueue(
            200,
            "{\"status\":\"error\",\"msg\":\"password or code is incorrect, you have 4 remaining"
                + " chances\"}")
        .enqueue(200, "{\"status\":\"ok\",\"data\":\"NextMfa\"}")
        .enqueue(200, "{\"status\":\"ok\",\"data\":null}")
        .enqueue(200, "{\"status\":\"ok\",\"data\":\"code-2\"}")
        .enqueue(200, "{\"access_token\":\"" + jwt("{\"email_verified\":false}") + "\"}")
        .enqueue(200, "{\"status\":\"ok\",\"data\":\"code-3\"}")
        .enqueue(200, "{\"token_type\":\"Bearer\"}");
    try (CasdoorClient c = client(settings())) {
      assertThatThrownBy(() -> c.signIn("alice", "nope", null))
          .isInstanceOf(AuthenticationException.class);
      assertThatThrownBy(() -> c.signIn("erin", "Password-123", null))
          .isInstanceOf(AuthenticationException.class)
          .hasMessageContaining("mfa_required");
      assertThatThrownBy(() -> c.signIn("x", "y", null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.signIn("x", "y", "123456"))
          .isInstanceOf(PermissionDeniedException.class);
      assertThatThrownBy(() -> c.signIn("x", "y", null)).isInstanceOf(ValidationException.class);
      assertThatThrownBy(() -> c.signIn("x", "", null)).isInstanceOf(ValidationException.class);
    }
    try (CasdoorClient c = client(settings().redirectUri(null))) {
      assertThatThrownBy(() -> c.signIn("x", "y", null)).isInstanceOf(ConfigException.class);
    }
  }

  @Test
  void signInWithTotpUsesTheSameSession() {
    server
        .enqueue(
            200,
            "{\"status\":\"ok\",\"data\":\"NextMfa\"}",
            "Set-Cookie",
            "casdoor_session_id=s1; Path=/")
        .enqueue(200, "{\"status\":\"ok\",\"data\":\"code-9\"}")
        .enqueue(200, "{\"access_token\":\"" + jwt("{\"email_verified\":true}") + "\"}");
    try (CasdoorClient c = client(settings())) {
      assertThat(c.signIn("erin", "Password-123", "123456").accessToken()).isNotEmpty();
      assertThat(server.requests().get(1).header("Cookie")).isEqualTo("casdoor_session_id=s1");
      assertThat(server.requests().get(1).body()).contains("\"passcode\":\"123456\"");
      assertThat(server.requests().get(1).body()).doesNotContain("Password-123");
    }
  }

  @Test
  void realCasdoorSignIn() {
    String url = System.getenv("GROW_CASDOOR_IT_URL");
    String user = System.getenv("GROW_CASDOOR_IT_USER");
    if (url == null || user == null) {
      return; // needs a real Casdoor (see the TypeScript/Go/Python suites for the setup)
    }
    var s =
        CasdoorAuthSettings.builder()
            .clientId(System.getenv("GROW_CASDOOR_IT_CLIENT_ID"))
            .clientSecret(System.getenv("GROW_CASDOOR_IT_CLIENT_SECRET"))
            .organization(System.getenv("GROW_CASDOOR_IT_ORG"))
            .application(System.getenv("GROW_CASDOOR_IT_APP"))
            .redirectUri(System.getenv("GROW_CASDOOR_IT_REDIRECT"))
            .build();
    try (CasdoorClient c = CasdoorClient.builder().url(url).settings(s).build()) {
      assertThat(c.health().healthy()).isTrue();
      c.ping();
      TokenSet t = c.signIn(user, System.getenv("GROW_CASDOOR_IT_PASSWORD"), null);
      TokenSet t2 = c.refresh(t.refreshToken().orElseThrow());
      assertThat(t2.accessToken()).isNotEqualTo(t.accessToken());
      c.signOut(t2.accessToken());
      c.signOut(t2.accessToken());
    }
  }

  @Test
  void exchangeAndAuthorizeUrl() {
    server
        .enqueue(200, "{\"access_token\":\"" + jwt("{\"email_verified\":false}") + "\"}")
        .enqueue(200, "{\"status\":\"error\",\"msg\":\"Please login first\"}");
    try (CasdoorClient c = client(settings().allowUnverifiedEmail(true).clientSecret(null))) {
      assertThat(c.exchangeCode("c", "v", "https://app.test/cb").accessToken()).isNotEmpty();
      assertThatThrownBy(() -> c.exchangeCode("c", "v", "r"))
          .isInstanceOf(AuthenticationException.class);
      String url = c.buildAuthorizeUrl("https://app.test/cb", "st", "ch");
      assertThat(url)
          .startsWith("https://auth.example.test/login/oauth/authorize?client_id=cid")
          .contains("code_challenge_method=S256");
      assertThatThrownBy(() -> c.buildAuthorizeUrl("", "s", "c"))
          .isInstanceOf(ValidationException.class);
    }
    CasdoorClient closed = client(settings());
    closed.close();
    assertThatThrownBy(() -> closed.buildAuthorizeUrl("r", "s", "c"))
        .isInstanceOf(CancelledException.class);
    try (CasdoorClient c = client(settings().publicUrl(null))) {
      assertThat(c.buildAuthorizeUrl("r", "s", "c")).startsWith(server.url());
    }
  }

  @Test
  void helpersAndErrorMapping() {
    var p = CasdoorFlows.createPkce();
    assertThat(p.codeChallenge()).isEqualTo(CasdoorFlows.pkceChallenge(p.codeVerifier()));
    assertThat(p.toString()).doesNotContain(p.codeVerifier());
    assertThat(CasdoorFlows.pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        .isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assertThat(CasdoorFlows.randomState()).isNotEqualTo(CasdoorFlows.randomState());
    assertThat(CasdoorFlows.payload("x")).isEmpty();
    assertThat(CasdoorFlows.payload("a.!!!.c")).isEmpty();
    assertThat(CasdoorFlows.envelopeError("op", "Phone number is invalid in your region US"))
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("empty password");
    assertThat(CasdoorFlows.envelopeError("op", "you can only send one code in 60s"))
        .isInstanceOf(RateLimitException.class);
    assertThat(CasdoorFlows.envelopeError("op", "Unauthorized operation"))
        .isInstanceOf(PermissionDeniedException.class);
    assertThat(CasdoorFlows.envelopeError("op", "duplicate key"))
        .isInstanceOf(ConflictException.class);
    assertThat(CasdoorFlows.envelopeError("op", "The user doesn't exist"))
        .isInstanceOf(NotFoundException.class);
    assertThat(CasdoorFlows.envelopeError("op", "The login method is not enabled"))
        .isInstanceOf(UnsupportedException.class);
    assertThat(CasdoorFlows.envelopeError("op", "")).isInstanceOf(ValidationException.class);
    assertThat(CasdoorFlows.oauthError("t", "unsupported_grant_type", ""))
        .isInstanceOf(UnsupportedException.class);
    assertThat(CasdoorFlows.oauthError("t", "invalid_request", "x"))
        .isInstanceOf(ValidationException.class);
  }
}
