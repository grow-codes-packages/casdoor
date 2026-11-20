package casdoor

import (
	"fmt"
	"net/url"
	"strings"
)

// DefaultURL is the default endpoint of Casdoor.
const DefaultURL = "http://127.0.0.1:8000"

// DefaultScope is the OAuth scope requested by sign-in and the authorize URL.
const DefaultScope = "openid profile email"

// vendorEnv lists the platform/vendor variables consulted after GROW_CASDOOR_*.
var vendorEnv = VendorEnv{URL: []string{"GROW_AUTH_ISSUER", "GROW_AUTH_PUBLIC_URL", "CASDOOR_URL"}}

// envNames maps a GROW_CASDOOR_<suffix> to its platform fallbacks.
var envNames = map[string][]string{
	"PUBLIC_URL":     {"GROW_AUTH_PUBLIC_URL"},
	"CLIENT_ID":      {"GROW_AUTH_CLIENT_ID"},
	"CLIENT_SECRET":  {"GROW_AUTH_CLIENT_SECRET"},
	"ORG":            {"GROW_AUTH_ORG"},
	"APP":            {"GROW_AUTH_APP"},
	"REDIRECT_URL":   {"GROW_AUTH_REDIRECT_URL"},
	"ADMIN_USERNAME": {"CASDOOR_ADMIN_USERNAME"},
	"ADMIN_PASSWORD": {"CASDOOR_ADMIN_PASSWORD"},
}

// Config configures a Client. Build it with a struct literal or ConfigFromEnv;
// zero values mean "use the default". Call Validate to check it.
type Config struct {
	CommonConfig

	// PublicURL is the browser-facing Casdoor URL for BuildAuthorizeURL
	// (env GROW_CASDOOR_PUBLIC_URL, GROW_AUTH_PUBLIC_URL). Default: URL.
	PublicURL string
	// ClientID is the OAuth client id (env GROW_CASDOOR_CLIENT_ID, GROW_AUTH_CLIENT_ID).
	ClientID string
	// ClientSecret is the OAuth client secret (env GROW_CASDOOR_CLIENT_SECRET, GROW_AUTH_CLIENT_SECRET).
	ClientSecret Secret
	// Organization is the Casdoor organization (env GROW_CASDOOR_ORG, GROW_AUTH_ORG).
	Organization string
	// Application is the Casdoor application name (env GROW_CASDOOR_APP, GROW_AUTH_APP).
	Application string
	// RedirectURI is the default code-flow redirect URI (env GROW_CASDOOR_REDIRECT_URL, GROW_AUTH_REDIRECT_URL).
	RedirectURI string
	// Scope is the OAuth scope (env GROW_CASDOOR_SCOPE). Default DefaultScope.
	Scope string
	// AdminUsername is the built-in admin (env GROW_CASDOOR_ADMIN_USERNAME, CASDOOR_ADMIN_USERNAME). Default "admin".
	AdminUsername string
	// AdminPassword enables the admin session for admin operations (env GROW_CASDOOR_ADMIN_PASSWORD,
	// CASDOOR_ADMIN_PASSWORD). Without it admin operations use the client credentials (HTTP Basic).
	AdminPassword Secret
	// AdminOrganization of the admin user (env GROW_CASDOOR_ADMIN_ORG). Default "built-in".
	AdminOrganization string
	// AdminApplication of the admin user (env GROW_CASDOOR_ADMIN_APP). Default "app-built-in".
	AdminApplication string
	// AllowUnverifiedEmail accepts tokens of users whose e-mail is not verified
	// (env GROW_CASDOOR_REQUIRE_VERIFIED_EMAIL=false). Default false: EmailNotVerified errors.
	AllowUnverifiedEmail bool
}

// ConfigFromEnv reads the configuration from the process environment.
func ConfigFromEnv() (Config, error) { return ConfigFromEnvWith(Config{}, nil) }

// ConfigFromEnvWith resolves explicit values > GROW_CASDOOR_* > platform
// variables (GROW_AUTH_*, CASDOOR_ADMIN_*) > defaults. env replaces the process
// environment when non-nil.
func ConfigFromEnvWith(explicit Config, env map[string]string) (Config, error) {
	r := NewEnvReader(EnvPrefix, env)
	c := explicit
	if err := c.applyEnv(r, vendorEnv); err != nil {
		return Config{}, err
	}
	str := func(dst *string, suffix string) {
		if *dst == "" {
			if v, ok := r.String(suffix, envNames[suffix]...); ok {
				*dst = v
			}
		}
	}
	str(&c.PublicURL, "PUBLIC_URL")
	str(&c.ClientID, "CLIENT_ID")
	str(&c.Organization, "ORG")
	str(&c.Application, "APP")
	str(&c.RedirectURI, "REDIRECT_URL")
	str(&c.Scope, "SCOPE")
	str(&c.AdminUsername, "ADMIN_USERNAME")
	str(&c.AdminOrganization, "ADMIN_ORG")
	str(&c.AdminApplication, "ADMIN_APP")
	sec := func(dst *Secret, suffix string) {
		if dst.IsZero() {
			if v, ok := r.String(suffix, envNames[suffix]...); ok {
				*dst = NewSecret(v)
			}
		}
	}
	sec(&c.ClientSecret, "CLIENT_SECRET")
	sec(&c.AdminPassword, "ADMIN_PASSWORD")
	if !c.AllowUnverifiedEmail {
		v, ok, err := r.Bool("REQUIRE_VERIFIED_EMAIL")
		if err != nil {
			return Config{}, err
		}
		if ok && !v {
			c.AllowUnverifiedEmail = true
		}
	}
	c.CommonConfig = c.withDefaults(DefaultURL)
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// withServiceDefaults fills the Casdoor defaults.
func (c Config) withServiceDefaults() Config {
	c.CommonConfig = c.withDefaults(DefaultURL)
	if c.PublicURL == "" {
		c.PublicURL = c.URL
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.Scope == "" {
		c.Scope = DefaultScope
	}
	if c.AdminUsername == "" {
		c.AdminUsername = "admin"
	}
	if c.AdminOrganization == "" {
		c.AdminOrganization = "built-in"
	}
	if c.AdminApplication == "" {
		c.AdminApplication = "app-built-in"
	}
	return c
}

// Validate checks the configuration and returns a CONFIG error.
func (c Config) Validate() error {
	if err := c.withDefaults(DefaultURL).validate(); err != nil {
		return err
	}
	d := c.withServiceDefaults()
	if u, err := url.Parse(d.PublicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return NewError(ErrorCodeConfig, "invalid configuration: PublicURL must be an http(s) URL", nil)
	}
	if !c.ClientSecret.IsZero() && strings.TrimSpace(c.ClientSecret.Reveal()) == "" {
		return NewError(ErrorCodeConfig, "invalid configuration: ClientSecret must not be blank", nil)
	}
	if !c.AdminPassword.IsZero() && strings.TrimSpace(c.AdminPassword.Reveal()) == "" {
		return NewError(ErrorCodeConfig, "invalid configuration: AdminPassword must not be blank", nil)
	}
	return nil
}

// String renders the configuration with every credential redacted.
func (c Config) String() string {
	return fmt.Sprintf("Config{%s PublicURL:%s ClientID:%s ClientSecret:%s Organization:%s Application:%s AdminPassword:%s}",
		c.describe(), RedactURL(c.PublicURL), c.ClientID, c.ClientSecret, c.Organization, c.Application, c.AdminPassword)
}

// GoString renders the configuration with every credential redacted.
func (c Config) GoString() string { return c.String() }
