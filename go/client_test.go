package casdoor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, base string, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{CommonConfig: CommonConfig{URL: base, Retry: fastRetry(0)}, PublicURL: "https://auth.example.test/",
		ClientID: "cid", ClientSecret: NewSecret("csecret"), Organization: "acme", Application: "app-acme",
		RedirectURI: "https://app.test/cb"}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func addUser(f *fakeCasdoor, name string, extra obj) {
	u := obj{"owner": "acme", "name": name, "email": name + "@acme.test", "password": "Password-123", "emailVerified": true}
	for k, v := range extra {
		u[k] = v
	}
	f.users["acme/"+name] = u
}

type result[T any] struct {
	v   T
	err error
}

func got[T any](v T, err error) result[T] { return result[T]{v, err} }

func (r result[T]) must(t *testing.T) T {
	t.Helper()
	if r.err != nil {
		t.Fatalf("unexpected error: %v", r.err)
	}
	return r.v
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func wantCode(t *testing.T, err error, code ErrorCode, reason string) {
	t.Helper()
	if CodeOf(err) != code || (reason != "" && ReasonOf(err) != reason) {
		t.Fatalf("want %s/%s, got %v (%s/%s)", code, reason, err, CodeOf(err), ReasonOf(err))
	}
}

func stubServer(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(h))
	t.Cleanup(s.Close)
	return s.URL
}

func TestConfigEnv(t *testing.T) {
	env := map[string]string{
		"GROW_AUTH_ISSUER": "http://casdoor:8000", "GROW_AUTH_PUBLIC_URL": "https://auth.example.test/",
		"GROW_AUTH_CLIENT_ID": "client-1", "GROW_AUTH_CLIENT_SECRET": "secret-1", "GROW_AUTH_ORG": "acme",
		"GROW_AUTH_APP": "app-acme", "GROW_AUTH_REDIRECT_URL": "https://app.test/cb", "CASDOOR_ADMIN_PASSWORD": "adm1n-pass",
		EnvPrefix + "ORG": "override", EnvPrefix + "SCOPE": "openid", EnvPrefix + "REQUIRE_VERIFIED_EMAIL": "false",
	}
	cfg := got(ConfigFromEnvWith(Config{Application: "explicit"}, env)).must(t)
	if cfg.URL != "http://casdoor:8000" || cfg.PublicURL != "https://auth.example.test/" || cfg.ClientID != "client-1" ||
		cfg.ClientSecret.Reveal() != "secret-1" || cfg.Organization != "override" || cfg.Application != "explicit" ||
		cfg.RedirectURI != "https://app.test/cb" || cfg.AdminPassword.Reveal() != "adm1n-pass" || cfg.Scope != "openid" ||
		!cfg.AllowUnverifiedEmail {
		t.Fatalf("env config: %s", cfg)
	}
	if s := cfg.String() + fmt.Sprintf("%#v", cfg); strings.Contains(s, "secret-1") || strings.Contains(s, "adm1n-pass") {
		t.Fatalf("leak: %s", s)
	}
	if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "REQUIRE_VERIFIED_EMAIL": "maybe"}); CodeOf(err) != ErrorCodeConfig {
		t.Fatalf("bool: %v", err)
	}
	if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "URL": "nope"}); CodeOf(err) != ErrorCodeConfig {
		t.Fatalf("url: %v", err)
	}
	if _, err := ConfigFromEnvWith(Config{}, map[string]string{EnvPrefix + "CONNECT_TIMEOUT": "x"}); CodeOf(err) != ErrorCodeConfig {
		t.Fatalf("duration: %v", err)
	}
	d := Config{}.withServiceDefaults()
	if d.URL != DefaultURL || d.PublicURL != DefaultURL || d.Scope != DefaultScope || d.AdminUsername != "admin" ||
		d.AdminOrganization != "built-in" || d.AdminApplication != "app-built-in" {
		t.Fatalf("defaults: %+v", d)
	}
	for _, bad := range []Config{{PublicURL: "ftp://x"}, {ClientSecret: NewSecret(" ")}, {AdminPassword: NewSecret(" ")}} {
		if _, err := NewClient(bad); CodeOf(err) != ErrorCodeConfig {
			t.Fatalf("validate %v: %v", bad, err)
		}
	}
	t.Setenv(EnvPrefix+"URL", "http://casdoor.test:8000")
	c := got(NewClientFromEnv()).must(t)
	defer func() { _ = c.Close() }()
	if c.Config().URL != "http://casdoor.test:8000" {
		t.Fatal(c.Config().URL)
	}
}

func TestCoreCalls(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	c := newTestClient(t, f.srv.URL, nil)
	if hs := got(c.Health(ctx)).must(t); !hs.Healthy {
		t.Fatalf("health %+v", hs)
	}
	got(c.Ping(ctx)).must(t)
	_, err := c.ServerVersion(ctx)
	wantCode(t, err, ErrorCodePermissionDenied, ReasonForbidden)
	admin := newTestClient(t, f.srv.URL, func(c *Config) { c.AdminPassword = NewSecret(fakeAdminPassword) })
	if v := got(admin.ServerVersion(ctx)).must(t); v != "v4.27.1" {
		t.Fatal(v)
	}
	got(admin.Ping(ctx)).must(t)
	_, err = newTestClient(t, f.srv.URL, func(c *Config) { c.ClientSecret = NewSecret("wrong") }).Ping(ctx)
	wantCode(t, err, ErrorCodeAuthentication, ReasonLoginRequired)
	_, err = newTestClient(t, f.srv.URL, func(c *Config) { c.AdminPassword = NewSecret("wrong-pass") }).ServerVersion(ctx)
	wantCode(t, err, ErrorCodeAuthentication, ReasonInvalidCredentials)
	_, err = newTestClient(t, f.srv.URL, func(c *Config) { c.ClientSecret = Secret{} }).Ping(ctx)
	wantCode(t, err, ErrorCodeConfig, "")
	_, err = newTestClient(t, f.srv.URL, func(c *Config) { c.ClientID = "" }).Ping(ctx)
	wantCode(t, err, ErrorCodeConfig, "")

	unhealthy := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","msg":"db"}`))
	})
	if hs := got(newTestClient(t, unhealthy, nil).Health(ctx)).must(t); hs.Healthy || hs.Status != "error" {
		t.Fatalf("unhealthy %+v", hs)
	}
	empty := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/login") {
			w.Header().Add("Set-Cookie", "casdoor_session_id=x")
		}
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	_, err = newTestClient(t, empty, func(c *Config) { c.AdminPassword = NewSecret("pw-123456") }).ServerVersion(ctx)
	wantCode(t, err, ErrorCodeUnsupported, "")

	c2 := newTestClient(t, f.srv.URL, nil)
	_ = c2.Close()
	_ = c2.Close()
	_, err = c2.SignIn(ctx, SignInInput{Username: "a", Password: "b"})
	wantCode(t, err, ErrorCodeCancelled, "")
	_, err = c2.BuildAuthorizeURL(AuthorizeURLInput{RedirectURI: "r", State: "s", CodeChallenge: "c"})
	wantCode(t, err, ErrorCodeCancelled, "")
}

func TestAdminRelogin(t *testing.T) {
	logins, gets := 0, 0
	base := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			logins++
			if r.URL.Query().Get("nocookie") == "" {
				w.Header().Add("Set-Cookie", fmt.Sprintf("casdoor_session_id=s%d", logins))
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		gets++
		if gets == 1 {
			_, _ = w.Write([]byte(`{"status":"error","msg":"Please login first"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"version":"v1"}}`))
	})
	c := newTestClient(t, base, func(c *Config) { c.AdminPassword = NewSecret("pw-123456") })
	if v := got(c.ServerVersion(context.Background())).must(t); v != "v1" || logins != 2 {
		t.Fatalf("%s %d", v, logins)
	}
	noCookie := stubServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	_, err := newTestClient(t, noCookie, func(c *Config) { c.AdminPassword = NewSecret("pw-123456") }).ServerVersion(context.Background())
	wantCode(t, err, ErrorCodeConfig, "")
	badJSON := stubServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`<html>`)) })
	_, err = newTestClient(t, badJSON, nil).Ping(context.Background())
	wantCode(t, err, ErrorCodeUnavailable, "")
	_, err = newTestClient(t, badJSON, nil).Refresh(context.Background(), "rt")
	wantCode(t, err, ErrorCodeUnavailable, "")
}

func TestSignUpVerifySignIn(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	c := newTestClient(t, f.srv.URL, nil)
	r := got(c.SignUp(ctx, SignUpInput{Email: "new.user@acme.test", Password: "Password-123", DisplayName: "New"})).must(t)
	if *r != (SignUpResult{UserID: "acme/new-user", Organization: "acme", Name: "new-user"}) {
		t.Fatalf("%+v", r)
	}
	_, err := c.SignIn(ctx, SignInInput{Username: "new.user@acme.test", Password: "Password-123"})
	if !IsEmailNotVerified(err) {
		t.Fatalf("want unverified: %v", err)
	}
	noErr(t, c.SendEmailVerification(ctx, "new.user@acme.test", PurposeAuto))
	code := f.mails["new.user@acme.test"]
	wantCode(t, c.VerifyEmail(ctx, VerifyEmailInput{Email: "new.user@acme.test", Code: "000000"}), ErrorCodeAuthentication, ReasonInvalidCredentials)
	noErr(t, c.VerifyEmail(ctx, VerifyEmailInput{Email: "new.user@acme.test", Code: code}))
	noErr(t, c.VerifyEmail(ctx, VerifyEmailInput{Email: "new.user@acme.test", Code: code}))
	tok := got(c.SignIn(ctx, SignInInput{Username: "new.user@acme.test", Password: "Password-123"})).must(t)
	if tok.RefreshToken == "" || tok.ExpiresAt.IsZero() || tok.TokenType != "Bearer" || strings.Contains(tok.String(), tok.AccessToken) {
		t.Fatalf("tokens %s", tok)
	}
	if decodeJWTPayload(tok.AccessToken)["name"] != "new-user" {
		t.Fatal("payload")
	}
	// sign-up with code + fallback id
	lax := newTestClient(t, f.srv.URL, func(c *Config) { c.AllowUnverifiedEmail = true })
	noErr(t, lax.SendEmailVerification(ctx, "code.user@acme.test", PurposeSignUp))
	r = got(lax.SignUp(ctx, SignUpInput{Username: "code_user", Email: "code.user@acme.test", Password: "Password-123", EmailCode: f.mails["code.user@acme.test"]})).must(t)
	if r.UserID != "acme/code_user" {
		t.Fatal(r.UserID)
	}
	stub := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":"Affected"}`))
	})
	if r := got(newTestClient(t, stub, func(c *Config) { c.Organization = "o" }).SignUp(ctx, SignUpInput{Email: "x@y.z", Password: "p"})).must(t); r.UserID != "o/x" {
		t.Fatal(r.UserID)
	}
}

func TestInputAndConfigErrors(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	addUser(f, "alice", nil)
	c := newTestClient(t, f.srv.URL, nil)
	_, err := c.SignIn(ctx, SignInInput{Username: "alice", Password: "nope"})
	wantCode(t, err, ErrorCodeAuthentication, ReasonInvalidCredentials)
	var d *ErrorDetail
	if !errors.As(err, &d) || d.CasdoorCode != "wrong-password" || d.Error() == "" || !errors.Is(err, ErrAuthentication) {
		t.Fatalf("detail %+v", d)
	}
	checks := []error{
		second(c.SignIn(ctx, SignInInput{Username: "alice"})),
		second(c.SignUp(ctx, SignUpInput{Email: "a@b.c", Password: " "})),
		second(c.Refresh(ctx, "")),
		c.SignOut(ctx, ""),
		c.ResetPassword(ctx, ResetPasswordInput{Email: "a@b.c", Code: "1"}),
		c.SendEmailVerification(ctx, "a@b.c", "other"),
		c.SendEmailVerification(ctx, "", PurposeAuto),
		c.VerifyEmail(ctx, VerifyEmailInput{}),
		c.ForgotPassword(ctx, ""),
		second(c.ExchangeCode(ctx, ExchangeCodeInput{})),
		second(c.SetupTOTP(ctx, "")),
		c.VerifyTOTP(ctx, VerifyTOTPInput{}),
		second(c.BuildAuthorizeURL(AuthorizeURLInput{})),
		second(c.EnsureOrganization(ctx, EnsureOrganizationInput{})),
		second(c.EnsureUser(ctx, EnsureUserInput{})),
		c.AssignRoles(ctx, "", nil, ""),
		second(c.EnsureEmailProvider(ctx, SMTPSettings{})),
		second(c.EnsureEmailProvider(ctx, SMTPSettings{Host: "h", From: "f"})),
	}
	for i, err := range checks {
		wantCode(t, err, ErrorCodeValidation, "")
		_ = i
	}
	noRedirect := newTestClient(t, f.srv.URL, func(c *Config) { c.RedirectURI = "" })
	wantCode(t, second(noRedirect.SignIn(ctx, SignInInput{Username: "a", Password: "b"})), ErrorCodeConfig, "")
	noOrg := newTestClient(t, f.srv.URL, func(c *Config) { c.Organization = "" })
	for _, err := range []error{
		second(noOrg.SignUp(ctx, SignUpInput{Email: "a@b.c", Password: "p"})),
		second(noOrg.SignIn(ctx, SignInInput{Username: "a", Password: "b"})),
		noOrg.VerifyEmail(ctx, VerifyEmailInput{Email: "a@b.c", Code: "1"}),
		noOrg.ForgotPassword(ctx, "a@b.c"),
		second(noOrg.EnsureApplication(ctx, EnsureApplicationInput{})),
		second(noOrg.EnsureRoles(ctx, []string{"x"}, "")),
		second(noOrg.EnsureUser(ctx, EnsureUserInput{Email: "a@b.c"})),
		noOrg.AssignRoles(ctx, "a", nil, ""),
	} {
		wantCode(t, err, ErrorCodeConfig, "")
	}
	noApp := newTestClient(t, f.srv.URL, func(c *Config) { c.Application = "" })
	for _, err := range []error{
		second(noApp.SignUp(ctx, SignUpInput{Email: "a@b.c", Password: "p"})),
		second(noApp.SignIn(ctx, SignInInput{Username: "a", Password: "b"})),
		noApp.SendEmailVerification(ctx, "a@b.c", PurposeSignUp),
		noApp.VerifyEmail(ctx, VerifyEmailInput{Email: "a@b.c", Code: "1"}),
		second(noApp.EnsureApplication(ctx, EnsureApplicationInput{})),
	} {
		wantCode(t, err, ErrorCodeConfig, "")
	}
	noID := newTestClient(t, f.srv.URL, func(c *Config) { c.ClientID = "" })
	for _, err := range []error{
		second(noID.SignIn(ctx, SignInInput{Username: "a", Password: "b"})),
		second(noID.ExchangeCode(ctx, ExchangeCodeInput{Code: "c", CodeVerifier: "v", RedirectURI: "r"})),
		second(noID.Refresh(ctx, "r")),
		second(noID.BuildAuthorizeURL(AuthorizeURLInput{RedirectURI: "r", State: "s", CodeChallenge: "c"})),
	} {
		wantCode(t, err, ErrorCodeConfig, "")
	}
}

func second[T any](_ T, err error) error { return err }

func TestRefreshSignOutAndOAuthErrors(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	addUser(f, "bob", nil)
	c := newTestClient(t, f.srv.URL, nil)
	tok := got(c.SignIn(ctx, SignInInput{Username: "bob", Password: "Password-123", RedirectURI: "https://app.test/cb"})).must(t)
	tok2 := got(c.Refresh(ctx, tok.RefreshToken)).must(t)
	if tok2.AccessToken == tok.AccessToken {
		t.Fatal("same token")
	}
	wantCode(t, second(c.Refresh(ctx, tok.RefreshToken)), ErrorCodeAuthentication, ReasonInvalidGrant)
	noErr(t, c.SignOut(ctx, tok2.AccessToken))
	noErr(t, c.SignOut(ctx, tok2.AccessToken))

	stub := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/logout":
			_, _ = w.Write([]byte(`{"status":"error","msg":"Unauthorized operation"}`))
		case r.URL.Path == "/api/login":
			_, _ = w.Write([]byte(`{"status":"ok","data":null}`))
		case strings.HasSuffix(r.URL.Path, "refresh_token") && r.URL.Query().Get("x") == "":
			_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
		case strings.HasSuffix(r.URL.Path, "access_token"):
			_, _ = w.Write([]byte(`{"status":"error","msg":"Please login first"}`))
		case r.URL.Path == "/api/get-application":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"status":"error","msg":"Unauthorized operation"}`))
		case r.URL.Path == "/api/mfa/setup/initiate":
			_, _ = w.Write([]byte(`{"status":"ok","data":{}}`))
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"x":1}`))
		}
	})
	s := newTestClient(t, stub, nil)
	wantCode(t, s.SignOut(ctx, "t"), ErrorCodePermissionDenied, ReasonForbidden)
	wantCode(t, second(s.SignIn(ctx, SignInInput{Username: "a", Password: "b"})), ErrorCodeValidation, "")
	wantCode(t, second(s.Refresh(ctx, "rt")), ErrorCodeValidation, "")
	wantCode(t, second(s.ExchangeCode(ctx, ExchangeCodeInput{Code: "c", CodeVerifier: "v", RedirectURI: "r"})), ErrorCodeAuthentication, ReasonLoginRequired)
	wantCode(t, second(s.Ping(ctx)), ErrorCodePermissionDenied, ReasonForbidden)
	wantCode(t, second(s.ServerVersion(ctx)), ErrorCodeValidation, "")
	token := "x." + b64json(obj{"owner": "o", "name": "n"}) + ".y"
	wantCode(t, second(s.SetupTOTP(ctx, token)), ErrorCodeValidation, "")

	oauthBodies := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "refresh_token") {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"x"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"expired"}`))
	})
	o := newTestClient(t, oauthBodies, nil)
	wantCode(t, second(o.Refresh(ctx, "rt")), ErrorCodeAuthentication, ReasonInvalidClient)
	wantCode(t, second(o.ExchangeCode(ctx, ExchangeCodeInput{Code: "c", CodeVerifier: "v", RedirectURI: "r"})), ErrorCodeAuthentication, ReasonInvalidGrant)
}

func TestAuthorizeURLAndExchange(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	addUser(f, "carol", nil)
	c := newTestClient(t, f.srv.URL, nil)
	p := NewPKCE()
	if p.CodeChallenge != PKCEChallenge(p.CodeVerifier) || p.CodeChallengeMethod != "S256" || sameState() {
		t.Fatal("pkce")
	}
	raw := got(c.BuildAuthorizeURL(AuthorizeURLInput{RedirectURI: "https://app.test/cb", State: "s1", CodeChallenge: p.CodeChallenge,
		Nonce: "n1", Scope: "openid", Extra: map[string]string{"prompt": "login"}})).must(t)
	u, _ := url.Parse(raw)
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != "https://auth.example.test/login/oauth/authorize" || q.Get("client_id") != "cid" ||
		q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" || q.Get("nonce") != "n1" || q.Get("scope") != "openid" {
		t.Fatal(raw)
	}
	_, err := c.ExchangeCode(ctx, ExchangeCodeInput{Code: f.browserCode(t, "carol", "Password-123", p.CodeChallenge), CodeVerifier: "wrong", RedirectURI: "https://app.test/cb"})
	wantCode(t, err, ErrorCodeAuthentication, ReasonInvalidGrant)
	tok := got(c.ExchangeCode(ctx, ExchangeCodeInput{Code: f.browserCode(t, "carol", "Password-123", p.CodeChallenge), CodeVerifier: p.CodeVerifier, RedirectURI: "https://app.test/cb"})).must(t)
	if !strings.Contains(tok.AccessToken, ".") {
		t.Fatal(tok)
	}
	bad := newTestClient(t, f.srv.URL, func(c *Config) { c.ClientSecret = NewSecret("wrong-secret") })
	wantCode(t, second(bad.ExchangeCode(ctx, ExchangeCodeInput{Code: "x", CodeVerifier: "y", RedirectURI: "z"})), ErrorCodeAuthentication, ReasonInvalidClient)
	// public client (no secret) still sends the code flow
	pub := newTestClient(t, f.srv.URL, func(c *Config) { c.ClientSecret = Secret{} })
	wantCode(t, second(pub.SignIn(ctx, SignInInput{Username: "carol", Password: "Password-123"})), ErrorCodeAuthentication, ReasonInvalidClient)
}

func TestEmailCodesAndPasswordReset(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	addUser(f, "dave", nil)
	addUser(f, "dup", nil)
	c := newTestClient(t, f.srv.URL, nil)
	noErr(t, c.SendEmailVerification(ctx, "fresh@acme.test", PurposeAuto))
	err := c.SendEmailVerification(ctx, "fresh@acme.test", PurposeAuto)
	wantCode(t, err, ErrorCodeRateLimited, ReasonRateLimited)
	var e *Error
	if !errors.As(err, &e) || e.RetryAfter != time.Minute || e.Retryable {
		t.Fatalf("retry after %+v", e)
	}
	wantCode(t, c.SendEmailVerification(ctx, "other@acme.test", PurposeVerify), ErrorCodeNotFound, ReasonNotFound)
	wantCode(t, c.SendEmailVerification(ctx, "dup@acme.test", PurposeSignUp), ErrorCodeConflict, ReasonAlreadyExists)
	noErr(t, c.SendEmailVerification(ctx, "ghost@acme.test", PurposeSignUp))
	wantCode(t, c.VerifyEmail(ctx, VerifyEmailInput{Email: "ghost@acme.test", Code: f.mails["ghost@acme.test"]}), ErrorCodeValidation, "")
	noErr(t, c.ForgotPassword(ctx, "dave@acme.test"))
	code := f.mails["dave@acme.test"]
	wantCode(t, c.ResetPassword(ctx, ResetPasswordInput{Email: "dave@acme.test", Code: "999999", NewPassword: "New-Password-456"}), ErrorCodeAuthentication, "")
	noErr(t, c.ResetPassword(ctx, ResetPasswordInput{Email: "dave@acme.test", Code: code, NewPassword: "New-Password-456"}))
	wantCode(t, second(c.SignIn(ctx, SignInInput{Username: "dave", Password: "Password-123"})), ErrorCodeAuthentication, "")
	got(c.SignIn(ctx, SignInInput{Username: "dave", Password: "New-Password-456"})).must(t)
	wantCode(t, c.ForgotPassword(ctx, "nobody@acme.test"), ErrorCodeNotFound, "")
	wantCode(t, c.ResetPassword(ctx, ResetPasswordInput{Email: "nobody@acme.test", Code: code, NewPassword: "x-123456789"}), ErrorCodeNotFound, "")
	noCreds := newTestClient(t, f.srv.URL, func(c *Config) { c.ClientSecret = Secret{} })
	wantCode(t, noCreds.ForgotPassword(ctx, "dave@acme.test"), ErrorCodeConfig, "")
	wantCode(t, noCreds.ResetPassword(ctx, ResetPasswordInput{Email: "dave@acme.test", Code: "1", NewPassword: "x"}), ErrorCodeConfig, "")
}

func TestTOTP(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	addUser(f, "erin", nil)
	c := newTestClient(t, f.srv.URL, nil)
	tok := got(c.SignIn(ctx, SignInInput{Username: "erin", Password: "Password-123"})).must(t)
	wantCode(t, second(c.SetupTOTP(ctx, tok.AccessToken)), ErrorCodePermissionDenied, ReasonForbidden)
	f.orgs["admin/acme"]["mfaItems"] = []any{map[string]any{"name": "app", "rule": "Optional"}}
	s := got(c.SetupTOTP(ctx, tok.AccessToken)).must(t)
	if len(s.RecoveryCodes) != 1 || strings.Contains(s.String(), s.Secret) {
		t.Fatalf("%v", s)
	}
	wantCode(t, c.VerifyTOTP(ctx, VerifyTOTPInput{AccessToken: tok.AccessToken, Secret: s.Secret, Code: "000000", RecoveryCode: "rc-1"}), ErrorCodeValidation, "")
	if _, ok := f.users["acme/erin"]["totpSecret"]; ok {
		t.Fatal("enabled without verify")
	}
	code := got(TOTPCode(s.Secret, time.Now())).must(t)
	noErr(t, c.VerifyTOTP(ctx, VerifyTOTPInput{AccessToken: tok.AccessToken, Secret: s.Secret, Code: code, RecoveryCode: "rc-1"}))
	_, err := c.SignIn(ctx, SignInInput{Username: "erin", Password: "Password-123"})
	var d *ErrorDetail
	if !IsMFARequired(err) || !errors.As(err, &d) || len(d.MFATypes) != 1 || d.MFATypes[0] != "app" {
		t.Fatalf("mfa %v", err)
	}
	got(c.SignIn(ctx, SignInInput{Username: "erin", Password: "Password-123", TOTPCode: code})).must(t)
	got(c.SignIn(ctx, SignInInput{Username: "erin", Password: "Password-123", RecoveryCode: "rc-1"})).must(t)
	wantCode(t, second(c.SignIn(ctx, SignInInput{Username: "erin", Password: "Password-123", TOTPCode: "000000"})), ErrorCodeAuthentication, ReasonInvalidCredentials)
	wantCode(t, second(c.SetupTOTP(ctx, "opaque")), ErrorCodeValidation, "")
	wantCode(t, c.VerifyTOTP(ctx, VerifyTOTPInput{AccessToken: "opaque", Secret: "s", Code: "1", RecoveryCode: "r"}), ErrorCodeValidation, "")
	// expired bearer → HTTP 401 envelope
	delete(f.access, tok.AccessToken)
	wantCode(t, second(c.SetupTOTP(ctx, tok.AccessToken)), ErrorCodeAuthentication, ReasonLoginRequired)
}

func TestAdminSetup(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	c := newTestClient(t, f.srv.URL, func(c *Config) {
		c.AdminPassword, c.Organization, c.Application = NewSecret(fakeAdminPassword), "shop", "app-shop"
		c.ClientID, c.ClientSecret = "shop-client", NewSecret("shop-secret-0123456789")
	})
	if created := got(c.EnsureOrganization(ctx, EnsureOrganizationInput{Name: "shop", DisplayName: "Shop"})).must(t); !created {
		t.Fatal("org not created")
	}
	if created := got(c.EnsureOrganization(ctx, EnsureOrganizationInput{Name: "shop", DisplayName: "Shop"})).must(t); created {
		t.Fatal("org created twice")
	}
	got(c.EnsureOrganization(ctx, EnsureOrganizationInput{Name: "shop", DisableTOTP: true, PasswordOptions: []string{"AtLeast12"}})).must(t)
	if fmt.Sprint(f.orgs["admin/shop"]["passwordOptions"]) != "[AtLeast12]" {
		t.Fatal(f.orgs["admin/shop"])
	}
	app := got(c.EnsureApplication(ctx, EnsureApplicationInput{RedirectURIs: []string{"https://shop.test/cb"}, Providers: []string{"provider-mail"}})).must(t)
	if app.ClientID != "shop-client" || app.ClientSecret.Reveal() != "shop-secret-0123456789" || !app.Created {
		t.Fatalf("%+v", app)
	}
	again := got(c.EnsureApplication(ctx, EnsureApplicationInput{RedirectURIs: []string{"https://shop.test/cb", "https://b.test/cb"}, SignUpEmailCode: true})).must(t)
	if again.Created || len(again.RedirectURIs) != 2 {
		t.Fatalf("%+v", again)
	}
	stored := f.apps["admin/app-shop"]
	if stored["tokenFormat"] != "JWT" || stored["enablePassword"] != true || len(stored["providers"].([]any)) != 1 {
		t.Fatalf("%v", stored)
	}
	if created := got(c.EnsureEmailProvider(ctx, SMTPSettings{Name: "provider-mail", Host: "mailpit", Port: 1025, From: "no-reply@shop.test", DisableSSL: true})).must(t); !created {
		t.Fatal("provider")
	}
	if created := got(c.EnsureEmailProvider(ctx, SMTPSettings{Name: "provider-mail", Host: "mailpit2", Port: 1025, From: "no-reply@shop.test", Password: NewSecret("smtp-pw")})).must(t); created {
		t.Fatal("provider twice")
	}
	if f.providers["admin/provider-mail"]["host"] != "mailpit2" || f.providers["admin/provider-mail"]["clientId2"] != "no-reply@shop.test" {
		t.Fatal(f.providers)
	}
	got(c.EnsureEmailProvider(ctx, SMTPSettings{Name: "provider-2", Host: "h", Port: 25, From: "a@b.c"})).must(t)
	if len(f.apps["admin/app-shop"]["providers"].([]any)) != 2 {
		t.Fatal("providers on app")
	}
	roles := got(c.EnsureRoles(ctx, []string{"buyer", "seller"}, "")).must(t)
	if len(roles) != 2 || !roles[0].Created {
		t.Fatal(roles)
	}
	if roles := got(c.EnsureRoles(ctx, []string{"buyer"}, "shop")).must(t); roles[0].Created {
		t.Fatal("role twice")
	}
	wantCode(t, second(c.EnsureRoles(ctx, []string{""}, "")), ErrorCodeValidation, "")
	u := got(c.EnsureUser(ctx, EnsureUserInput{Email: "buyer@shop.test", Password: NewSecret("Password-123"), Roles: []string{"buyer"}})).must(t)
	if u.UserID != "shop/buyer" || !u.EmailVerified || !u.Created {
		t.Fatalf("%+v", u)
	}
	u2 := got(c.EnsureUser(ctx, EnsureUserInput{Email: "buyer@shop.test", Password: NewSecret("Password-456"), DisplayName: "B", Roles: []string{"buyer", "admin"}})).must(t)
	if u2.Created || u2.DisplayName != "B" || f.users["shop/buyer"]["password"] != "Password-456" {
		t.Fatalf("%+v %v", u2, f.users["shop/buyer"])
	}
	if fmt.Sprint(f.roles["shop/buyer"]["users"]) != "[shop/buyer]" || fmt.Sprint(f.roles["shop/admin"]["users"]) != "[shop/buyer]" {
		t.Fatal(f.roles)
	}
	if u3 := got(c.EnsureUser(ctx, EnsureUserInput{Email: "buyer@shop.test"})).must(t); u3.Created {
		t.Fatal("u3")
	}
	noErr(t, c.AssignRoles(ctx, "buyer@shop.test", []string{"seller"}, ""))
	noErr(t, c.AssignRoles(ctx, "shop/buyer", []string{"seller"}, ""))
	if fmt.Sprint(f.roles["shop/seller"]["users"]) != "[shop/buyer]" {
		t.Fatal(f.roles["shop/seller"])
	}
	wantCode(t, c.AssignRoles(ctx, "nobody", []string{"seller"}, ""), ErrorCodeNotFound, "")
	gen := newTestClient(t, f.srv.URL, func(c *Config) {
		c.AdminPassword, c.ClientID, c.ClientSecret = NewSecret(fakeAdminPassword), "", Secret{}
	})
	info := got(gen.EnsureApplication(ctx, EnsureApplicationInput{Name: "app-new", Organization: "shop"})).must(t)
	if len(info.ClientID) != 20 || len(info.ClientSecret.Reveal()) != 40 {
		t.Fatalf("%+v", info)
	}
	basic := newTestClient(t, f.srv.URL, nil)
	if a := got(basic.EnsureApplication(ctx, EnsureApplicationInput{RedirectURIs: []string{"https://app.test/cb"}})).must(t); a.ClientSecret.Reveal() != "csecret" {
		t.Fatal(a)
	}
}

func TestAdminMaskedAndNotCreated(t *testing.T) {
	ctx := context.Background()
	masked := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			w.Header().Add("Set-Cookie", "casdoor_session_id=x")
		}
		if r.URL.Path == "/api/get-application" {
			_, _ = w.Write([]byte(`{"status":"ok","data":{"owner":"admin","name":"a","clientSecret":"***","cert":"***","samlReplyUrl":"***"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	c := newTestClient(t, masked, func(c *Config) { c.AdminPassword, c.Organization, c.Application = NewSecret("pw-123456"), "o", "a" })
	wantCode(t, second(c.EnsureApplication(ctx, EnsureApplicationInput{RedirectURIs: []string{"x"}})), ErrorCodePermissionDenied, ReasonMaskedObject)
	unmatched := newTestClient(t, masked, func(c *Config) {
		c.AdminPassword, c.Organization, c.Application, c.ClientSecret = NewSecret("pw-123456"), "o", "a", Secret{}
	})
	_, err := unmatched.EnsureApplication(ctx, EnsureApplicationInput{RedirectURIs: []string{"x"}})
	wantCode(t, err, ErrorCodePermissionDenied, ReasonMaskedObject)
	empty := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" {
			w.Header().Add("Set-Cookie", "casdoor_session_id=x")
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":null}`))
	})
	e := newTestClient(t, empty, func(c *Config) { c.AdminPassword, c.Organization, c.Application = NewSecret("pw-123456"), "o", "a" })
	wantCode(t, second(e.EnsureApplication(ctx, EnsureApplicationInput{})), ErrorCodeValidation, "")
	wantCode(t, second(e.EnsureUser(ctx, EnsureUserInput{Email: "a@b.c", Password: NewSecret("Password-1")})), ErrorCodeValidation, "")
	wantCode(t, second(e.EnsureUser(ctx, EnsureUserInput{Email: "a@b.c"})), ErrorCodeValidation, "")
	if created := got(e.EnsureOrganization(ctx, EnsureOrganizationInput{Name: "o"})).must(t); !created {
		t.Fatal("org")
	}
	failing := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","msg":"Unauthorized operation"}`))
	})
	fl := newTestClient(t, failing, nil)
	for _, err := range []error{
		second(fl.EnsureOrganization(ctx, EnsureOrganizationInput{Name: "o"})),
		second(fl.EnsureApplication(ctx, EnsureApplicationInput{})),
		second(fl.EnsureEmailProvider(ctx, SMTPSettings{Host: "h", Port: 1, From: "f"})),
		second(fl.EnsureRoles(ctx, []string{"r"}, "")),
		second(fl.EnsureUser(ctx, EnsureUserInput{Email: "a@b.c"})),
		fl.AssignRoles(ctx, "a@b.c", []string{"r"}, ""),
		fl.AssignRoles(ctx, "a", []string{"r"}, ""),
		fl.VerifyEmail(ctx, VerifyEmailInput{Email: "a@b.c", Code: "1"}),
		fl.ForgotPassword(ctx, "a@b.c"),
	} {
		wantCode(t, err, ErrorCodePermissionDenied, ReasonForbidden)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		msg    string
		code   ErrorCode
		reason string
	}{
		{"Phone number is invalid in your region US", ErrorCodeValidation, ReasonEmptyCredential},
		{"password or code is incorrect, you have 4 remaining chances", ErrorCodeAuthentication, ReasonInvalidCredentials},
		{"Please login first", ErrorCodeAuthentication, ReasonLoginRequired},
		{"Unauthorized operation", ErrorCodePermissionDenied, ReasonForbidden},
		{"too many times, please wait for 15 minutes", ErrorCodeRateLimited, ReasonLocked},
		{"the account is frozen", ErrorCodePermissionDenied, ReasonLocked},
		{"you can only send one code in 60s", ErrorCodeRateLimited, ReasonRateLimited},
		{`pq: duplicate key value violates unique constraint "x"`, ErrorCodeConflict, ReasonAlreadyExists},
		{"The user: acme/x doesn't exist", ErrorCodeNotFound, ReasonNotFound},
		{"The login method: login with email is not enabled", ErrorCodeUnsupported, ReasonNotEnabled},
		{"something else", ErrorCodeValidation, ReasonOther},
	}
	for _, tc := range cases {
		err := envelopeError("op", tc.msg, "c1", 200)
		wantCode(t, err, tc.code, tc.reason)
		if !strings.HasPrefix(err.Message, "op: ") {
			t.Fatal(err.Message)
		}
	}
	if !strings.Contains(envelopeError("op", "Phone number is invalid", "", 200).Message, "empty password") {
		t.Fatal("hint")
	}
	if e := envelopeError("op", "too many times, please wait for 15 minutes", "", 200); e.RetryAfter != 15*time.Minute {
		t.Fatal(e.RetryAfter)
	}
	if e := envelopeError("op", "rate limit, retry in 5 s", "", 200); e.RetryAfter != 5*time.Second {
		t.Fatal(e.RetryAfter)
	}
	if !strings.Contains(envelopeError("op", "", "", 200).Message, "status error") || len(envelopeError("op", strings.Repeat("x", 400), "", 200).Message) > 320 {
		t.Fatal("text")
	}
	if ReasonOf(errors.New("x")) != "" {
		t.Fatal("reason of plain error")
	}
	wantCode(t, oauthError("t", "invalid_grant", "the account is frozen", 400), ErrorCodePermissionDenied, ReasonLocked)
	wantCode(t, oauthError("t", "unsupported_grant_type", "", 400), ErrorCodeUnsupported, ReasonNotEnabled)
	wantCode(t, oauthError("t", "invalid_request", "", 400), ErrorCodeValidation, ReasonOther)
	if !IsMFARequired(oauthError("t", "invalid_grant", "the user has MFA enabled", 400)) {
		t.Fatal("mfa")
	}
}

func TestHelpers(t *testing.T) {
	if code := got(TOTPCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))).must(t); code != "287082" {
		t.Fatal(code)
	}
	if _, err := TOTPCode("!!!", time.Now()); CodeOf(err) != ErrorCodeValidation {
		t.Fatal(err)
	}
	if decodeJWTPayload("abc") != nil || decodeJWTPayload("a.!!!.c") != nil || decodeJWTPayload("a.MQ.c") != nil {
		t.Fatal("jwt")
	}
	if userNameFor("john.doe@x.test", "") != "john-doe" || userNameFor("x@y", "valid_name") != "valid_name" ||
		userNameFor("@y", "") != "user" || len(userNameFor(strings.Repeat("a", 50)+"@x", "")) != 39 {
		t.Fatal("names")
	}
	if _, err := tokenSetFrom("op", obj{"access_token": "a", "expires_in": float64(0)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if stringList([]string{"a"})[0] != "a" || len(stringList(nil)) != 0 {
		t.Fatal("stringList")
	}
	if jsonUnmarshal(nil, &struct{}{}) != nil {
		t.Fatal("unmarshal")
	}
	j := newCookieJar()
	h := http.Header{}
	h.Add("Set-Cookie", "a=1; Path=/")
	h.Add("Set-Cookie", "broken")
	h.Add("Set-Cookie", "a=2")
	j.absorb(h)
	if j.header() != "a=2" {
		t.Fatal(j.header())
	}
}

// sameState reports whether two RandomState calls collide (they must not).
func sameState() bool {
	a, b := RandomState(), RandomState()
	return a == b
}
