package casdoor

// Integration test against a real Casdoor + Mailpit (skipped unless GROW_CASDOOR_IT_URL is set).
// Env: GROW_CASDOOR_IT_URL, GROW_CASDOOR_IT_ADMIN_PASSWORD, GROW_CASDOOR_IT_MAILPIT (Mailpit HTTP
// URL seen from the test), GROW_CASDOOR_IT_SMTP_HOST (Mailpit SMTP host seen from Casdoor).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func itMailCode(t *testing.T, to string, since time.Time) string {
	t.Helper()
	mailpit := os.Getenv("GROW_CASDOOR_IT_MAILPIT")
	re := regexp.MustCompile(`\b(\d{6})\b`)
	for range 60 {
		res, err := http.Get(mailpit + "/api/v1/search?query=" + url.QueryEscape("to:"+to))
		if err == nil {
			var found struct {
				Messages []struct {
					ID      string
					Created time.Time
				}
			}
			_ = json.NewDecoder(res.Body).Decode(&found)
			_ = res.Body.Close()
			for _, m := range found.Messages {
				if m.Created.After(since.Add(-2 * time.Second)) {
					r2, err := http.Get(mailpit + "/api/v1/message/" + m.ID)
					if err != nil {
						continue
					}
					var full struct{ Text string }
					_ = json.NewDecoder(r2.Body).Decode(&full)
					_ = r2.Body.Close()
					if mm := re.FindStringSubmatch(full.Text); mm != nil {
						return mm[1]
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("no mail for %s", to)
	return ""
}

func TestRealCasdoor(t *testing.T) {
	base := os.Getenv("GROW_CASDOOR_IT_URL")
	if base == "" {
		t.Skip("GROW_CASDOOR_IT_URL is not set")
	}
	ctx := context.Background()
	rid := randomHex(3)
	org, app, redirect := "itgo-"+rid, "app-itgo-"+rid, "https://app.test/auth/callback"
	common := Config{CommonConfig: CommonConfig{URL: base}, Organization: org, Application: app,
		ClientID: "cid-" + rid, ClientSecret: NewSecret(randomHex(20)), RedirectURI: redirect}
	buyer := "buyer-" + rid + "@example.test"

	acfg := common
	acfg.AdminPassword = NewSecret(os.Getenv("GROW_CASDOOR_IT_ADMIN_PASSWORD"))
	admin := got(NewClient(acfg)).must(t)
	defer func() { _ = admin.Close() }()
	if hs := got(admin.Health(ctx)).must(t); !hs.Healthy {
		t.Fatal(hs)
	}
	if v := got(admin.ServerVersion(ctx)).must(t); !strings.HasPrefix(v, "v") {
		t.Fatal(v)
	}
	if !got(admin.EnsureOrganization(ctx, EnsureOrganizationInput{Name: org})).must(t) {
		t.Fatal("org")
	}
	info := got(admin.EnsureApplication(ctx, EnsureApplicationInput{RedirectURIs: []string{redirect}})).must(t)
	if !info.Created || info.ClientSecret.Reveal() != common.ClientSecret.Reveal() {
		t.Fatalf("%+v", info)
	}
	smtpHost := os.Getenv("GROW_CASDOOR_IT_SMTP_HOST")
	got(admin.EnsureEmailProvider(ctx, SMTPSettings{Name: "provider-mail-" + rid, Host: smtpHost, Port: 1025, From: "no-reply@" + org + ".test", DisableSSL: true})).must(t)
	got(admin.EnsureRoles(ctx, []string{"buyer", "seller"}, "")).must(t)
	got(admin.EnsureUser(ctx, EnsureUserInput{Email: buyer, Password: NewSecret("Password-123"), Roles: []string{"buyer"}})).must(t)
	got(admin.EnsureUser(ctx, EnsureUserInput{Email: buyer, Password: NewSecret("Password-456")})).must(t)
	noErr(t, admin.AssignRoles(ctx, buyer, []string{"seller"}, ""))
	got(admin.Ping(ctx)).must(t)

	c := got(NewClient(common)).must(t)
	defer func() { _ = c.Close() }()
	wantCode(t, second(c.SignIn(ctx, SignInInput{Username: buyer, Password: "Password-123"})), ErrorCodeAuthentication, ReasonInvalidCredentials)
	tok := got(c.SignIn(ctx, SignInInput{Username: buyer, Password: "Password-456"})).must(t)
	var roles []string
	for _, r := range decodeJWTPayload(tok.AccessToken)["roles"].([]any) {
		roles = append(roles, r.(map[string]any)["name"].(string))
	}
	sort.Strings(roles)
	if strings.Join(roles, ",") != "buyer,seller" {
		t.Fatal(roles)
	}
	tok2 := got(c.Refresh(ctx, tok.RefreshToken)).must(t)
	noErr(t, c.SignOut(ctx, tok2.AccessToken))
	noErr(t, c.SignOut(ctx, tok2.AccessToken))

	newUser := "new-" + rid + "@example.test"
	if r := got(c.SignUp(ctx, SignUpInput{Email: newUser, Password: "Password-123"})).must(t); r.UserID != org+"/new-"+rid {
		t.Fatal(r.UserID)
	}
	if _, err := c.SignIn(ctx, SignInInput{Username: newUser, Password: "Password-123"}); !IsEmailNotVerified(err) {
		t.Fatal(err)
	}
	since := time.Now()
	noErr(t, c.SendEmailVerification(ctx, newUser, PurposeAuto))
	noErr(t, c.VerifyEmail(ctx, VerifyEmailInput{Email: newUser, Code: itMailCode(t, newUser, since)}))
	got(c.SignIn(ctx, SignInInput{Username: newUser, Password: "Password-123"})).must(t)

	since = time.Now()
	noErr(t, c.ForgotPassword(ctx, buyer))
	noErr(t, c.ResetPassword(ctx, ResetPasswordInput{Email: buyer, Code: itMailCode(t, buyer, since), NewPassword: "Password-789"}))
	tok3 := got(c.SignIn(ctx, SignInInput{Username: buyer, Password: "Password-789"})).must(t)

	s := got(c.SetupTOTP(ctx, tok3.AccessToken)).must(t)
	code := got(TOTPCode(s.Secret, time.Now())).must(t)
	noErr(t, c.VerifyTOTP(ctx, VerifyTOTPInput{AccessToken: tok3.AccessToken, Secret: s.Secret, Code: code, RecoveryCode: s.RecoveryCodes[0]}))
	if _, err := c.SignIn(ctx, SignInInput{Username: buyer, Password: "Password-789"}); !IsMFARequired(err) {
		t.Fatal(err)
	}
	got(c.SignIn(ctx, SignInInput{Username: buyer, Password: "Password-789", TOTPCode: code})).must(t)

	p := NewPKCE()
	got(c.BuildAuthorizeURL(AuthorizeURLInput{RedirectURI: redirect, State: RandomState(), CodeChallenge: p.CodeChallenge})).must(t)
	q := url.Values{"clientId": {common.ClientID}, "responseType": {"code"}, "redirectUri": {redirect}, "scope": {"openid"},
		"state": {"s"}, "code_challenge": {p.CodeChallenge}, "code_challenge_method": {"S256"}}
	body, _ := json.Marshal(obj{"application": app, "organization": org, "username": newUser, "password": "Password-123", "type": "code"})
	res, err := http.Post(base+"/api/login?"+q.Encode(), "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	var env struct{ Data string }
	_ = json.NewDecoder(res.Body).Decode(&env)
	_ = res.Body.Close()
	got(c.ExchangeCode(ctx, ExchangeCodeInput{Code: env.Data, CodeVerifier: p.CodeVerifier, RedirectURI: redirect})).must(t)
}
