package casdoor

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Client is the Casdoor client: user flows for backends-for-frontends and
// idempotent admin operations. Every Casdoor {"status":"error"} answer (HTTP
// 200) and every OAuth error becomes an *Error with the canonical code and a
// *ErrorDetail cause (ReasonOf). It is safe for concurrent use.
type Client struct {
	cfg       Config
	transport *httpTransport
	api       *api
	closeOnce sync.Once
}

// NewClient validates cfg and returns a client.
func NewClient(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withServiceDefaults()
	t, err := newHTTPTransport(cfg.CommonConfig)
	if err != nil {
		return nil, err
	}
	t.addSecret(cfg.ClientSecret.Reveal(), cfg.AdminPassword.Reveal())
	return &Client{cfg: cfg, transport: t, api: newAPI(cfg, t)}, nil
}

// NewClientFromEnv builds a client from the environment (see ConfigFromEnv):
// GROW_CASDOOR_*, then GROW_AUTH_ISSUER|PUBLIC_URL, GROW_AUTH_CLIENT_ID/SECRET,
// GROW_AUTH_ORG/APP, GROW_AUTH_REDIRECT_URL, CASDOOR_ADMIN_PASSWORD.
func NewClientFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewClient(cfg)
}

// Config returns the effective configuration.
func (c *Client) Config() Config { return c.cfg }

// Health checks GET /api/health without credentials. It reports an
// unreachable or unhealthy service in the result; it fails only for CANCELLED and CONFIG.
func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	hs, err := c.transport.checkHealth(ctx, "health", &request{Method: http.MethodGet, Path: "/api/health"})
	if err == nil && hs.Healthy && hs.Status != "ok" {
		hs.Healthy = false
		if hs.Status == "" {
			hs.Status = "unhealthy"
		}
	}
	return hs, err
}

// Ping makes an authenticated round trip with the admin credentials (admin
// session or client credentials) and returns its latency.
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	app := orDefault(c.cfg.Application, c.cfg.AdminApplication)
	if _, err := c.api.call(ctx, apiCall{op: "ping", path: "/api/get-application", query: url.Values{"id": {"admin/" + app}}, auth: authAdmin}); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// ServerVersion returns the Casdoor version (/api/get-version-info, admin session).
func (c *Client) ServerVersion(ctx context.Context) (string, error) {
	env, err := c.api.call(ctx, apiCall{op: "serverVersion", path: "/api/get-version-info", auth: authAdmin})
	if err != nil {
		return "", err
	}
	var data struct {
		Version string `json:"version"`
	}
	decodeData(env, &data)
	if data.Version == "" {
		return "", NewError(ErrorCodeUnsupported, "serverVersion: the service does not report a version", nil)
	}
	return data.Version, nil
}

// Close releases resources. It is idempotent.
func (c *Client) Close() error {
	c.closeOnce.Do(c.transport.close)
	return nil
}
