package codes.grow.packages.casdoor;

import codes.grow.packages.casdoor.core.EnvReader;
import codes.grow.packages.casdoor.core.Redaction;
import codes.grow.packages.casdoor.core.Secret;
import java.util.Optional;

/**
 * Casdoor application settings of the client (Java skeleton): OAuth client, organization,
 * application, redirect and public URLs.
 *
 * <p>Environment: {@code GROW_CASDOOR_<NAME>} first, then the platform names {@code
 * GROW_AUTH_CLIENT_ID/SECRET}, {@code GROW_AUTH_ORG/APP}, {@code GROW_AUTH_REDIRECT_URL}, {@code
 * GROW_AUTH_PUBLIC_URL}.
 */
public final class CasdoorAuthSettings {
  /** Default OAuth scope. */
  public static final String DEFAULT_SCOPE = "openid profile email";

  private final String clientId;
  private final Secret clientSecret;
  private final String organization;
  private final String application;
  private final String redirectUri;
  private final String publicUrl;
  private final String scope;
  private final boolean allowUnverifiedEmail;

  private CasdoorAuthSettings(Builder b) {
    this.clientId = b.clientId;
    this.clientSecret = b.clientSecret;
    this.organization = b.organization;
    this.application = b.application;
    this.redirectUri = b.redirectUri;
    this.publicUrl = b.publicUrl == null ? null : b.publicUrl.replaceAll("/+$", "");
    this.scope = b.scope == null ? DEFAULT_SCOPE : b.scope;
    this.allowUnverifiedEmail = b.allowUnverifiedEmail;
  }

  /**
   * Starts an empty builder.
   *
   * @return a builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Settings with nothing configured.
   *
   * @return empty settings
   */
  public static CasdoorAuthSettings empty() {
    return new Builder().build();
  }

  /**
   * Reads the settings from the environment.
   *
   * @param env environment reader
   * @return the settings
   */
  public static CasdoorAuthSettings fromEnv(EnvReader env) {
    return new Builder().fromEnv(env).build();
  }

  /**
   * OAuth client id.
   *
   * @return client id
   */
  public Optional<String> clientId() {
    return Optional.ofNullable(clientId);
  }

  /**
   * OAuth client secret.
   *
   * @return client secret
   */
  public Optional<Secret> clientSecret() {
    return Optional.ofNullable(clientSecret);
  }

  /**
   * Casdoor organization.
   *
   * @return organization
   */
  public Optional<String> organization() {
    return Optional.ofNullable(organization);
  }

  /**
   * Casdoor application.
   *
   * @return application
   */
  public Optional<String> application() {
    return Optional.ofNullable(application);
  }

  /**
   * Default redirect URI of the code flow.
   *
   * @return redirect URI
   */
  public Optional<String> redirectUri() {
    return Optional.ofNullable(redirectUri);
  }

  /**
   * Browser-facing URL (empty = the client URL).
   *
   * @return public URL
   */
  public Optional<String> publicUrl() {
    return Optional.ofNullable(publicUrl);
  }

  /**
   * OAuth scope.
   *
   * @return scope
   */
  public String scope() {
    return scope;
  }

  /**
   * Whether tokens of unverified e-mail addresses are accepted.
   *
   * @return true when allowed
   */
  public boolean allowUnverifiedEmail() {
    return allowUnverifiedEmail;
  }

  @Override
  public String toString() {
    return "CasdoorAuthSettings{clientId="
        + clientId
        + ", clientSecret="
        + (clientSecret == null ? "null" : Redaction.REDACTED)
        + ", organization="
        + organization
        + ", application="
        + application
        + "}";
  }

  /** Builder of the settings. */
  public static final class Builder {
    private String clientId;
    private Secret clientSecret;
    private String organization;
    private String application;
    private String redirectUri;
    private String publicUrl;
    private String scope;
    private boolean allowUnverifiedEmail;

    private Builder() {}

    /**
     * Fills every unset field from the environment.
     *
     * @param env environment reader
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      if (clientId == null) {
        clientId = env.string("CLIENT_ID", "GROW_AUTH_CLIENT_ID").orElse(null);
      }
      if (clientSecret == null) {
        clientSecret =
            env.string("CLIENT_SECRET", "GROW_AUTH_CLIENT_SECRET").map(Secret::of).orElse(null);
      }
      if (organization == null) {
        organization = env.string("ORG", "GROW_AUTH_ORG").orElse(null);
      }
      if (application == null) {
        application = env.string("APP", "GROW_AUTH_APP").orElse(null);
      }
      if (redirectUri == null) {
        redirectUri = env.string("REDIRECT_URL", "GROW_AUTH_REDIRECT_URL").orElse(null);
      }
      if (publicUrl == null) {
        publicUrl = env.string("PUBLIC_URL", "GROW_AUTH_PUBLIC_URL").orElse(null);
      }
      if (scope == null) {
        scope = env.string("SCOPE").orElse(null);
      }
      if (!allowUnverifiedEmail) {
        allowUnverifiedEmail = env.bool("REQUIRE_VERIFIED_EMAIL").map(v -> !v).orElse(false);
      }
      return this;
    }

    /**
     * Sets the client id.
     *
     * @param v value
     * @return this builder
     */
    public Builder clientId(String v) {
      this.clientId = v;
      return this;
    }

    /**
     * Sets the client secret.
     *
     * @param v value
     * @return this builder
     */
    public Builder clientSecret(String v) {
      this.clientSecret = v == null ? null : Secret.of(v);
      return this;
    }

    /**
     * Sets the organization.
     *
     * @param v value
     * @return this builder
     */
    public Builder organization(String v) {
      this.organization = v;
      return this;
    }

    /**
     * Sets the application.
     *
     * @param v value
     * @return this builder
     */
    public Builder application(String v) {
      this.application = v;
      return this;
    }

    /**
     * Sets the redirect URI.
     *
     * @param v value
     * @return this builder
     */
    public Builder redirectUri(String v) {
      this.redirectUri = v;
      return this;
    }

    /**
     * Sets the browser-facing URL.
     *
     * @param v value
     * @return this builder
     */
    public Builder publicUrl(String v) {
      this.publicUrl = v;
      return this;
    }

    /**
     * Sets the scope.
     *
     * @param v value
     * @return this builder
     */
    public Builder scope(String v) {
      this.scope = v;
      return this;
    }

    /**
     * Accepts tokens of unverified e-mail addresses.
     *
     * @param v value
     * @return this builder
     */
    public Builder allowUnverifiedEmail(boolean v) {
      this.allowUnverifiedEmail = v;
      return this;
    }

    /**
     * Builds the settings.
     *
     * @return the settings
     */
    public CasdoorAuthSettings build() {
      return new CasdoorAuthSettings(this);
    }
  }
}
