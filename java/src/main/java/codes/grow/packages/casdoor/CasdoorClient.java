package codes.grow.packages.casdoor;

import codes.grow.packages.casdoor.core.AuthenticationException;
import codes.grow.packages.casdoor.core.CancelledException;
import codes.grow.packages.casdoor.core.ConfigException;
import codes.grow.packages.casdoor.core.EnvReader;
import codes.grow.packages.casdoor.core.HealthCheck;
import codes.grow.packages.casdoor.core.HealthStatus;
import codes.grow.packages.casdoor.core.Hooks;
import codes.grow.packages.casdoor.core.HttpTransport;
import codes.grow.packages.casdoor.core.Logger;
import codes.grow.packages.casdoor.core.RetryPolicy;
import codes.grow.packages.casdoor.core.Secret;
import codes.grow.packages.casdoor.core.TlsOptions;
import codes.grow.packages.casdoor.core.TransportRequest;
import codes.grow.packages.casdoor.core.TransportResponse;
import codes.grow.packages.casdoor.core.UnsupportedException;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Client for Casdoor.
 *
 * <p>Implements SPEC section 2.4. Thread-safe; create one per endpoint and close it when done.
 *
 * <pre>{@code
 * try (CasdoorClient client = CasdoorClient.fromEnv()) {
 *   HealthStatus health = client.health();
 * }
 * }</pre>
 *
 * <p>Every I/O method has a blocking form and an {@code …Async} form returning {@link
 * CompletableFuture}. This file is owned by the service package (generated once by sdk-kit); add
 * service modules here.
 */
public final class CasdoorClient implements AutoCloseable {
  private final CasdoorConfig config;
  private final HttpTransport transport;
  private final AtomicBoolean closed = new AtomicBoolean();
  private final List<AutoCloseable> resources = new ArrayList<>();
  private final CasdoorAuthSettings settings;

  private CasdoorClient(CasdoorConfig config, CasdoorAuthSettings settings) {
    this.config = config;
    this.settings = settings;
    this.transport = new HttpTransport(config.toTransportConfig());
  }

  /**
   * Creates a client.
   *
   * @param config validated configuration
   * @return a new client
   * @throws ConfigException when TLS or proxy settings are invalid
   */
  public static CasdoorClient create(CasdoorConfig config) {
    return create(config, CasdoorAuthSettings.empty());
  }

  /**
   * Creates a client with Casdoor application settings.
   *
   * @param config validated configuration
   * @param settings client id/secret, organization, application, redirect and public URLs
   * @return a new client
   */
  public static CasdoorClient create(CasdoorConfig config, CasdoorAuthSettings settings) {
    config.validate();
    return new CasdoorClient(config, settings);
  }

  /**
   * Creates a client from the SDK and vendor environment variables.
   *
   * @return a new client
   */
  public static CasdoorClient fromEnv() {
    return builder().fromEnv(EnvReader.system()).build();
  }

  /**
   * Returns the Casdoor application settings.
   *
   * @return the settings
   */
  public CasdoorAuthSettings settings() {
    return settings;
  }

  /**
   * Starts a client builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the configuration.
   *
   * @return the configuration
   */
  public CasdoorConfig config() {
    return config;
  }

  /**
   * Returns the HTTP transport, for service modules built on this client.
   *
   * @return the transport
   */
  public HttpTransport transport() {
    return transport;
  }

  /**
   * Registers a resource (watcher, renewer, batch processor) closed with the client.
   *
   * @param resource the resource
   */
  public void register(AutoCloseable resource) {
    synchronized (resources) {
      resources.add(resource);
    }
  }

  /**
   * Checks liveness ({@code GET /api/health}). Never throws for an unhealthy or unreachable
   * service.
   *
   * @return the health status
   * @throws CancelledException when interrupted or closed
   */
  public HealthStatus health() {
    return HealthCheck.check(transport, "/api/health");
  }

  /**
   * Asynchronous {@link #health()}.
   *
   * @return a future with the health status
   */
  public CompletableFuture<HealthStatus> healthAsync() {
    return HealthCheck.checkAsync(transport, "/api/health");
  }

  /**
   * Performs an authenticated round trip ({@code GET /v1/ping}).
   *
   * @return the latency
   * @throws AuthenticationException on bad credentials
   */
  public Duration ping() {
    return HttpTransport.await(pingAsync(), "ping");
  }

  /**
   * Asynchronous {@link #ping()}.
   *
   * @return a future with the latency
   */
  public CompletableFuture<Duration> pingAsync() {
    long start = System.nanoTime();
    String app = settings.application().orElse("app-built-in");
    return transport
        .sendAsync(
            authorized(
                TransportRequest.get("/api/get-application")
                    .query("id", "admin/" + app)
                    .operation("ping")))
        .thenApply(
            r -> {
              CasdoorFlows.checkEnvelope("ping", CasdoorFlows.body(r));
              return Duration.ofNanos(System.nanoTime() - start);
            });
  }

  /**
   * Returns the server version ({@code GET /version}).
   *
   * @return the version string
   * @throws UnsupportedException when the server exposes none
   */
  public String serverVersion() {
    return HttpTransport.await(serverVersionAsync(), "serverVersion");
  }

  /**
   * Asynchronous {@link #serverVersion()}.
   *
   * @return a future with the version
   */
  public CompletableFuture<String> serverVersionAsync() {
    return transport
        .sendAsync(
            authorized(
                TransportRequest.get("/api/get-version-info")
                    .operation("serverVersion")
                    .acceptStatus(404)))
        .thenApply(CasdoorClient::version);
  }

  private static String version(TransportResponse r) {
    JsonNode body = r.status() == 404 ? null : CasdoorFlows.body(r);
    if (body != null && "error".equals(CasdoorFlows.text(body, "status"))) {
      throw new UnsupportedException("serverVersion: needs the admin session");
    }
    JsonNode v = body == null ? null : body.path("data").get("version");
    if (v == null || !v.isTextual()) {
      throw new UnsupportedException("serverVersion: the server exposes no version");
    }
    return v.asText();
  }

  private TransportRequest authorized(TransportRequest.Builder b) {
    if (settings.clientId().isPresent() && settings.clientSecret().isPresent()) {
      String pair = settings.clientId().get() + ":" + settings.clientSecret().get().reveal();
      b.header(
          "Authorization",
          "Basic "
              + java.util.Base64.getEncoder()
                  .encodeToString(pair.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } else {
      config.token().ifPresent(t -> b.header("Authorization", "Bearer " + t.reveal()));
    }
    return b.build();
  }

  private String need(String op, String name, java.util.Optional<String> v) {
    return v.orElseThrow(() -> new ConfigException(op + ": " + name + " is not configured"));
  }

  /**
   * Headless password sign-in: {@code /api/login} (code flow + PKCE) then the token endpoint.
   *
   * @param username user name or e-mail
   * @param password password
   * @param totpCode current TOTP code, or null
   * @return the tokens
   * @throws AuthenticationException on wrong credentials or when a second factor is required
   */
  public TokenSet signIn(String username, String password, String totpCode) {
    String op = "signIn";
    CasdoorFlows.required(op, "username", username);
    CasdoorFlows.required(op, "password", password);
    String redirect = need(op, "redirectUri", settings.redirectUri());
    String clientId = need(op, "clientId", settings.clientId());
    var pkce = CasdoorFlows.createPkce();
    var body = new java.util.LinkedHashMap<String, Object>();
    body.put("application", need(op, "application", settings.application()));
    body.put("organization", need(op, "organization", settings.organization()));
    body.put("username", username);
    body.put("password", password);
    body.put("type", "code");
    body.put("signinMethod", "Password");
    body.put("autoSignin", false);
    String state = CasdoorFlows.randomState();
    TransportResponse r = transport.send(login(op, clientId, redirect, state, pkce, body, null));
    JsonNode env = CasdoorFlows.checkEnvelope(op, CasdoorFlows.body(r));
    String code = CasdoorFlows.text(env, "data");
    if ("NextMfa".equals(code)) {
      if (totpCode == null || totpCode.isEmpty()) {
        throw new AuthenticationException(op + ": a second factor is required (mfa_required)");
      }
      // Same Casdoor session; the second step sends only the passcode.
      StringBuilder cookie = new StringBuilder();
      r.headers()
          .forEach(
              (k, values) -> {
                if ("set-cookie".equalsIgnoreCase(k)) {
                  for (String v : values) {
                    cookie.append(cookie.length() == 0 ? "" : "; ").append(v.split(";", 2)[0]);
                  }
                }
              });
      var second = new java.util.LinkedHashMap<String, Object>();
      second.put("application", body.get("application"));
      second.put("organization", body.get("organization"));
      second.put("type", "code");
      second.put("passcode", totpCode);
      second.put("mfaType", "app");
      TransportResponse r2 =
          transport.send(login(op, clientId, redirect, state, pkce, second, cookie.toString()));
      code = CasdoorFlows.text(CasdoorFlows.checkEnvelope(op, CasdoorFlows.body(r2)), "data");
    }
    if (code == null) {
      throw new codes.grow.packages.casdoor.core.ValidationException(
          op + ": Casdoor returned no authorization code");
    }
    return checkVerified(op, exchange(op, code, pkce.codeVerifier(), redirect));
  }

  private TransportRequest login(
      String op,
      String clientId,
      String redirect,
      String state,
      CasdoorFlows.Pkce pkce,
      java.util.Map<String, Object> body,
      String cookie) {
    var b =
        TransportRequest.post("/api/login")
            .query("clientId", clientId)
            .query("responseType", "code")
            .query("redirectUri", redirect)
            .query("scope", settings.scope())
            .query("state", state)
            .query("code_challenge", pkce.codeChallenge())
            .query("code_challenge_method", "S256")
            .json(body)
            .operation(op);
    if (cookie != null && !cookie.isEmpty()) {
      b.header("Cookie", cookie);
    }
    return b.build();
  }

  /**
   * Exchanges the authorization code of the browser redirect for tokens.
   *
   * @param code authorization code
   * @param codeVerifier PKCE verifier
   * @param redirectUri redirect URI used for the authorize request
   * @return the tokens
   */
  public TokenSet exchangeCode(String code, String codeVerifier, String redirectUri) {
    String op = "exchangeCode";
    CasdoorFlows.required(op, "code", code);
    CasdoorFlows.required(op, "codeVerifier", codeVerifier);
    CasdoorFlows.required(op, "redirectUri", redirectUri);
    return checkVerified(op, exchange(op, code, codeVerifier, redirectUri));
  }

  private TokenSet exchange(String op, String code, String verifier, String redirect) {
    var form = new java.util.LinkedHashMap<String, String>();
    form.put("grant_type", "authorization_code");
    form.put("code", code);
    form.put("code_verifier", verifier);
    form.put("redirect_uri", redirect);
    form.put("client_id", need(op, "clientId", settings.clientId()));
    form.put("client_secret", settings.clientSecret().map(s -> s.reveal()).orElse(null));
    return CasdoorFlows.tokenSet(op, oauth(op, "/api/login/oauth/access_token", form));
  }

  /**
   * New tokens from a refresh token.
   *
   * @param refreshToken refresh token
   * @return the tokens
   */
  public TokenSet refresh(String refreshToken) {
    String op = "refresh";
    CasdoorFlows.required(op, "refreshToken", refreshToken);
    var form = new java.util.LinkedHashMap<String, String>();
    form.put("grant_type", "refresh_token");
    form.put("refresh_token", refreshToken);
    form.put("client_id", need(op, "clientId", settings.clientId()));
    form.put("client_secret", settings.clientSecret().map(s -> s.reveal()).orElse(null));
    form.put("scope", settings.scope());
    return CasdoorFlows.tokenSet(op, oauth(op, "/api/login/oauth/refresh_token", form));
  }

  private JsonNode oauth(String op, String path, java.util.Map<String, String> form) {
    TransportResponse r =
        transport.send(
            TransportRequest.post(path)
                .body(
                    CasdoorFlows.form(form).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    "application/x-www-form-urlencoded")
                .acceptStatus(400, 401)
                .operation(op)
                .build());
    JsonNode body = CasdoorFlows.body(r);
    String error = CasdoorFlows.text(body, "error");
    if (error != null) {
      String desc =
          java.util.Optional.ofNullable(CasdoorFlows.text(body, "error_description")).orElse("");
      throw CasdoorFlows.oauthError(op, error, desc);
    }
    return CasdoorFlows.checkEnvelope(op, body);
  }

  private TokenSet checkVerified(String op, TokenSet t) {
    if (!settings.allowUnverifiedEmail()
        && CasdoorFlows.payload(t.accessToken())
            .map(p -> p.path("email_verified").isBoolean() && !p.path("email_verified").asBoolean())
            .orElse(false)) {
      throw new codes.grow.packages.casdoor.core.PermissionDeniedException(
          op + ": the e-mail address is not verified (email_not_verified)");
    }
    return t;
  }

  /**
   * Ends the Casdoor session of the token ({@code /api/logout}). Idempotent.
   *
   * @param token access or id token
   */
  public void signOut(String token) {
    String op = "signOut";
    CasdoorFlows.required(op, "token", token);
    TransportResponse r =
        transport.send(
            TransportRequest.post("/api/logout")
                .query("id_token_hint", token)
                .acceptStatus(401)
                .operation(op)
                .build());
    if (r.status() == 401) {
      return;
    }
    try {
      CasdoorFlows.checkEnvelope(op, CasdoorFlows.body(r));
    } catch (AuthenticationException e) {
      // an expired or revoked token is already signed out
    }
  }

  /**
   * Browser authorize URL (code flow, PKCE S256) on the public URL.
   *
   * @param redirectUri redirect URI
   * @param state state value
   * @param codeChallenge PKCE challenge
   * @return the URL
   */
  public String buildAuthorizeUrl(String redirectUri, String state, String codeChallenge) {
    String op = "buildAuthorizeUrl";
    if (closed.get()) {
      throw new CancelledException(op + ": client is closed");
    }
    CasdoorFlows.required(op, "redirectUri", redirectUri);
    CasdoorFlows.required(op, "state", state);
    CasdoorFlows.required(op, "codeChallenge", codeChallenge);
    var q = new java.util.LinkedHashMap<String, String>();
    q.put("client_id", need(op, "clientId", settings.clientId()));
    q.put("response_type", "code");
    q.put("redirect_uri", redirectUri);
    q.put("scope", settings.scope());
    q.put("state", state);
    q.put("code_challenge", codeChallenge);
    q.put("code_challenge_method", "S256");
    String base = settings.publicUrl().orElse(config.url().replaceAll("/+$", ""));
    return base + "/login/oauth/authorize?" + CasdoorFlows.form(q);
  }

  /**
   * Returns whether {@link #close()} was called.
   *
   * @return true once closed
   */
  public boolean isClosed() {
    return closed.get();
  }

  /** Stops registered resources and the transport. Idempotent. */
  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    List<AutoCloseable> copy;
    synchronized (resources) {
      copy = new ArrayList<>(resources);
      resources.clear();
    }
    for (AutoCloseable r : copy) {
      try {
        r.close();
      } catch (Exception ignored) {
        // best effort: close must not throw
      }
    }
    transport.close();
  }

  @Override
  public String toString() {
    return "CasdoorClient{" + config + "}";
  }

  /** Builder that configures and creates a client in one chain. */
  public static final class Builder {
    private final CasdoorConfig.Builder config = CasdoorConfig.builder();
    private CasdoorAuthSettings settings;
    private EnvReader env;

    private Builder() {}

    /**
     * Sets the Casdoor application settings (default: from the environment given to {@link
     * #fromEnv(EnvReader)}, else empty).
     *
     * @param settings settings
     * @return this builder
     */
    public Builder settings(CasdoorAuthSettings settings) {
      this.settings = settings;
      return this;
    }

    /**
     * Fills unset fields from an environment reader.
     *
     * @param env reader, e.g. {@link EnvReader#system()}
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      config.fromEnv(env);
      this.env = env;
      return this;
    }

    /**
     * Sets the endpoint base URL.
     *
     * @param url URL
     * @return this builder
     */
    public Builder url(String url) {
      config.url(url);
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(String token) {
      config.token(token);
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(Secret token) {
      config.token(token);
      return this;
    }

    /**
     * Sets the connect timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      config.connectTimeout(d);
      return this;
    }

    /**
     * Sets the per-attempt timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      config.requestTimeout(d);
      return this;
    }

    /**
     * Sets the total timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      config.totalTimeout(d);
      return this;
    }

    /**
     * Sets the retry policy.
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      config.retry(retry);
      return this;
    }

    /**
     * Sets the TLS options.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      config.tls(tls);
      return this;
    }

    /**
     * Sets the proxy URL.
     *
     * @param proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      config.proxy(proxy);
      return this;
    }

    /**
     * Adds a header.
     *
     * @param name name
     * @param value value
     * @return this builder
     */
    public Builder header(String name, String value) {
      config.header(name, value);
      return this;
    }

    /**
     * Sets the user agent suffix.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      config.userAgentSuffix(suffix);
      return this;
    }

    /**
     * Sets hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      config.hooks(hooks);
      return this;
    }

    /**
     * Sets the logger.
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      config.logger(logger);
      return this;
    }

    /**
     * Builds the configuration and the client.
     *
     * @return a new client
     * @throws ConfigException when the configuration is invalid
     */
    public CasdoorClient build() {
      CasdoorAuthSettings s = settings;
      if (s == null) {
        s = env == null ? CasdoorAuthSettings.empty() : CasdoorAuthSettings.fromEnv(env);
      }
      return create(config.build(), s);
    }
  }
}
