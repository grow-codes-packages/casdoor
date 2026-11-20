package casdoor

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const mfaTOTP = "app"

func tokenSetFrom(op string, body map[string]any, now time.Time) (*TokenSet, error) {
	access, _ := body["access_token"].(string)
	if access == "" {
		return nil, validationError(op, "Casdoor returned no access_token")
	}
	str := func(k string) string { v, _ := body[k].(string); return v }
	t := &TokenSet{AccessToken: access, RefreshToken: str("refresh_token"), IDToken: str("id_token"),
		TokenType: str("token_type"), Scope: str("scope")}
	if t.TokenType == "" {
		t.TokenType = "Bearer"
	}
	if exp, ok := body["expires_in"].(float64); ok && exp > 0 {
		t.ExpiresIn = int(exp)
		t.ExpiresAt = now.Add(time.Duration(exp) * time.Second)
	}
	return t, nil
}

func (c *Client) checkVerified(op string, t *TokenSet) (*TokenSet, error) {
	if c.cfg.AllowUnverifiedEmail {
		return t, nil
	}
	claims := decodeJWTPayload(t.AccessToken)
	v, ok := claims["email_verified"]
	if !ok {
		v = claims["emailVerified"]
	}
	if v == false {
		return nil, casdoorError(ErrorCodePermissionDenied, op+": the e-mail address is not verified",
			&ErrorDetail{Reason: ReasonEmailNotVerified}, 0)
	}
	return t, nil
}

func tokenUser(op, accessToken string) (owner, name string, err error) {
	claims := decodeJWTPayload(accessToken)
	owner, _ = claims["owner"].(string)
	name, _ = claims["name"].(string)
	if owner == "" || name == "" {
		return "", "", validationError(op, "the access token carries no Casdoor owner/name (use tokenFormat JWT)")
	}
	return owner, name, nil
}

// SignUp registers a user through /api/signup. Pass EmailCode when the
// application requires the e-mail code on sign-up.
func (c *Client) SignUp(ctx context.Context, in SignUpInput) (*SignUpResult, error) {
	const op = "signUp"
	if err := required(op, "email", in.Email, "password", in.Password); err != nil {
		return nil, err
	}
	org, err := c.api.organization(op, "")
	if err != nil {
		return nil, err
	}
	app, err := c.api.application(op, "")
	if err != nil {
		return nil, err
	}
	name := userNameFor(in.Email, in.Username)
	display := in.DisplayName
	if display == "" {
		display = name
	}
	env, err := c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/signup", jar: newCookieJar(),
		json: map[string]any{"application": app, "organization": org, "username": name, "name": name,
			"email": in.Email, "emailCode": in.EmailCode, "password": in.Password, "confirm": in.Password,
			"displayName": display, "agreement": true}})
	if err != nil {
		return nil, err
	}
	var id string
	if !decodeData(env, &id) || !strings.Contains(id, "/") {
		id = org + "/" + name
	}
	_, n, _ := strings.Cut(id, "/")
	return &SignUpResult{UserID: id, Organization: org, Name: n}, nil
}

// SignIn is the headless password sign-in (code flow + PKCE inside the BFF).
// It returns a ReasonMFARequired error (IsMFARequired) when the user has TOTP
// and no code was given, and ReasonEmailNotVerified when the e-mail is not verified.
func (c *Client) SignIn(ctx context.Context, in SignInInput) (*TokenSet, error) {
	const op = "signIn"
	if err := required(op, "username", in.Username, "password", in.Password); err != nil {
		return nil, err
	}
	redirect := in.RedirectURI
	if redirect == "" {
		redirect = c.cfg.RedirectURI
	}
	if redirect == "" {
		return nil, configError(op, "redirect URI is not configured")
	}
	clientID, err := c.api.clientID(op)
	if err != nil {
		return nil, err
	}
	app, err := c.api.application(op, "")
	if err != nil {
		return nil, err
	}
	org, err := c.api.organization(op, "")
	if err != nil {
		return nil, err
	}
	p := NewPKCE()
	mfa := map[string]any{}
	switch {
	case in.TOTPCode != "":
		mfa["passcode"], mfa["mfaType"] = in.TOTPCode, mfaTOTP
	case in.RecoveryCode != "":
		mfa["recoveryCode"], mfa["mfaType"] = in.RecoveryCode, mfaTOTP
	}
	q := url.Values{"clientId": {clientID}, "responseType": {"code"}, "redirectUri": {redirect}, "scope": {c.cfg.Scope},
		"state": {RandomState()}, "code_challenge": {p.CodeChallenge}, "code_challenge_method": {"S256"}}
	// One Casdoor session for both steps: the password step answers "NextMfa" and remembers
	// the user in the session; the second step sends only the passcode (no username/password).
	jar := newCookieJar()
	env, err := c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/login", query: q, jar: jar,
		json: map[string]any{"application": app, "organization": org, "username": in.Username, "password": in.Password,
			"type": "code", "signinMethod": "Password", "autoSignin": false}})
	if err != nil {
		return nil, err
	}
	var code string
	decodeData(env, &code)
	if code == "NextMfa" {
		if len(mfa) == 0 {
			var props []struct {
				MfaType string `json:"mfaType"`
			}
			var types []string
			_ = jsonUnmarshal(env.Data2, &props)
			for _, p := range props {
				if p.MfaType != "" {
					types = append(types, p.MfaType)
				}
			}
			return nil, casdoorError(ErrorCodeAuthentication, op+": a second factor is required",
				&ErrorDetail{Reason: ReasonMFARequired, MFATypes: types}, 0)
		}
		mfa["application"], mfa["organization"], mfa["type"] = app, org, "code"
		env, err = c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/login", query: q, jar: jar, json: mfa})
		if err != nil {
			return nil, err
		}
		code = ""
		decodeData(env, &code)
	}
	if code == "" {
		return nil, validationError(op, "Casdoor returned no authorization code")
	}
	t, err := c.exchange(ctx, op, code, p.CodeVerifier, redirect)
	if err != nil {
		return nil, err
	}
	return c.checkVerified(op, t)
}

func (c *Client) exchange(ctx context.Context, op, code, verifier, redirect string) (*TokenSet, error) {
	clientID, err := c.api.clientID(op)
	if err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {redirect}, "client_id": {clientID}}
	if !c.cfg.ClientSecret.IsZero() {
		form.Set("client_secret", c.cfg.ClientSecret.Reveal())
	}
	body, err := c.api.oauth(ctx, op, "/api/login/oauth/access_token", form)
	if err != nil {
		return nil, err
	}
	return tokenSetFrom(op, body, time.Now())
}

// ExchangeCode exchanges the authorization code of the browser redirect for tokens.
func (c *Client) ExchangeCode(ctx context.Context, in ExchangeCodeInput) (*TokenSet, error) {
	const op = "exchangeCode"
	if err := required(op, "code", in.Code, "codeVerifier", in.CodeVerifier, "redirectUri", in.RedirectURI); err != nil {
		return nil, err
	}
	t, err := c.exchange(ctx, op, in.Code, in.CodeVerifier, in.RedirectURI)
	if err != nil {
		return nil, err
	}
	return c.checkVerified(op, t)
}

// Refresh returns new tokens for a refresh token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	const op = "refresh"
	if err := required(op, "refreshToken", refreshToken); err != nil {
		return nil, err
	}
	clientID, err := c.api.clientID(op)
	if err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientID}, "scope": {c.cfg.Scope}}
	if !c.cfg.ClientSecret.IsZero() {
		form.Set("client_secret", c.cfg.ClientSecret.Reveal())
	}
	body, err := c.api.oauth(ctx, op, "/api/login/oauth/refresh_token", form)
	if err != nil {
		return nil, err
	}
	return tokenSetFrom(op, body, time.Now())
}

// SignOut ends the Casdoor session of the token (/api/logout). Idempotent: an
// expired or revoked token counts as signed out.
func (c *Client) SignOut(ctx context.Context, token string) error {
	const op = "signOut"
	if err := required(op, "token", token); err != nil {
		return err
	}
	_, err := c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/logout", query: url.Values{"id_token_hint": {token}}})
	if CodeOf(err) == ErrorCodeAuthentication {
		return nil
	}
	return err
}

func (c *Client) sendCode(ctx context.Context, op, email, method, checkUser string) error {
	app, err := c.api.application(op, "")
	if err != nil {
		return err
	}
	form := url.Values{"dest": {email}, "type": {"email"}, "applicationId": {"admin/" + app}, "method": {method},
		"captchaType": {"none"}, "captchaToken": {""}}
	if checkUser != "" {
		form.Set("checkUser", checkUser)
	}
	_, err = c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/send-verification-code", form: form, jar: newCookieJar()})
	return err
}

// SendEmailVerification mails a verification code. Casdoor allows one code per
// address per 60 s (RATE_LIMITED with RetryAfter).
func (c *Client) SendEmailVerification(ctx context.Context, email string, purpose EmailPurpose) error {
	const op = "sendEmailVerification"
	if err := required(op, "email", email); err != nil {
		return err
	}
	switch purpose {
	case PurposeSignUp:
		return c.sendCode(ctx, op, email, "signup", "")
	case PurposeAuto, PurposeVerify:
	default:
		return validationError(op, "purpose must be empty, signup or verify")
	}
	err := c.sendCode(ctx, op, email, "login", "")
	if purpose == PurposeAuto && CodeOf(err) == ErrorCodeNotFound {
		return c.sendCode(ctx, op, email, "signup", "")
	}
	return err
}

// userByEmail returns the raw user object for an e-mail (admin credentials), nil when missing.
func (c *Client) userByEmail(ctx context.Context, op, email string) (map[string]any, error) {
	org, err := c.api.organization(op, "")
	if err != nil {
		return nil, err
	}
	env, err := c.api.call(ctx, apiCall{op: op, path: "/api/get-user", query: url.Values{"owner": {org}, "email": {email}}, auth: authAdmin})
	if err != nil {
		return nil, err
	}
	var user map[string]any
	if !decodeData(env, &user) {
		return nil, nil
	}
	if name, _ := user["name"].(string); name == "" {
		return nil, nil
	}
	return user, nil
}

func (c *Client) verifyCode(ctx context.Context, op, email, code string, jar *cookieJar) error {
	app, err := c.api.application(op, "")
	if err != nil {
		return err
	}
	org, err := c.api.organization(op, "")
	if err != nil {
		return err
	}
	_, err = c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/verify-code", jar: jar,
		json: map[string]any{"application": app, "organization": org, "username": email, "name": email, "code": code, "type": "email"}})
	return err
}

// VerifyEmail checks the code and marks the user's e-mail verified
// (full-object update-user with the admin credentials).
func (c *Client) VerifyEmail(ctx context.Context, in VerifyEmailInput) error {
	const op = "verifyEmail"
	if err := required(op, "email", in.Email, "code", in.Code); err != nil {
		return err
	}
	if err := c.verifyCode(ctx, op, in.Email, in.Code, newCookieJar()); err != nil {
		return err
	}
	user, err := c.userByEmail(ctx, op, in.Email)
	if err != nil {
		return err
	}
	if user == nil {
		return validationError(op, "no user with this e-mail address exists yet (sign up with EmailCode instead)")
	}
	if user["emailVerified"] == true {
		return nil
	}
	user["emailVerified"] = true
	org, _ := c.api.organization(op, "")
	_, err = c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/update-user",
		query: url.Values{"id": {org + "/" + user["name"].(string)}}, json: user, auth: authAdmin})
	return err
}

// ForgotPassword mails a password reset code (NOT_FOUND for unknown e-mails;
// do not reveal that to the browser).
func (c *Client) ForgotPassword(ctx context.Context, email string) error {
	const op = "forgotPassword"
	if err := required(op, "email", email); err != nil {
		return err
	}
	user, err := c.userByEmail(ctx, op, email)
	if err != nil {
		return err
	}
	if user == nil {
		return NewError(ErrorCodeNotFound, op+": no user with this e-mail address", nil)
	}
	return c.sendCode(ctx, op, email, "forget", user["name"].(string))
}

// ResetPassword sets a new password with the code from ForgotPassword (code
// check and password change share one Casdoor session).
func (c *Client) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	const op = "resetPassword"
	if err := required(op, "email", in.Email, "code", in.Code, "newPassword", in.NewPassword); err != nil {
		return err
	}
	user, err := c.userByEmail(ctx, op, in.Email)
	if err != nil {
		return err
	}
	if user == nil {
		return NewError(ErrorCodeNotFound, op+": no user with this e-mail address", nil)
	}
	jar := newCookieJar()
	if err := c.verifyCode(ctx, op, in.Email, in.Code, jar); err != nil {
		return err
	}
	org, _ := c.api.organization(op, "")
	_, err = c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/set-password", jar: jar,
		form: url.Values{"userOwner": {org}, "userName": {user["name"].(string)}, "newPassword": {in.NewPassword}, "code": {in.Code}}})
	return err
}

// BuildAuthorizeURL returns the browser authorize URL on PublicURL (code flow, PKCE S256).
func (c *Client) BuildAuthorizeURL(in AuthorizeURLInput) (string, error) {
	const op = "buildAuthorizeUrl"
	if c.transport.closed.Load() {
		return "", NewError(ErrorCodeCancelled, op+": client is closed", nil)
	}
	if err := required(op, "redirectUri", in.RedirectURI, "state", in.State, "codeChallenge", in.CodeChallenge); err != nil {
		return "", err
	}
	clientID, err := c.api.clientID(op)
	if err != nil {
		return "", err
	}
	scope := in.Scope
	if scope == "" {
		scope = c.cfg.Scope
	}
	q := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {in.RedirectURI}, "scope": {scope},
		"state": {in.State}, "code_challenge": {in.CodeChallenge}, "code_challenge_method": {"S256"}}
	if in.Nonce != "" {
		q.Set("nonce", in.Nonce)
	}
	for k, v := range in.Extra {
		q.Set(k, v)
	}
	return c.cfg.PublicURL + "/login/oauth/authorize?" + q.Encode(), nil
}

// SetupTOTP starts TOTP enrollment for the user of the access token.
func (c *Client) SetupTOTP(ctx context.Context, accessToken string) (*TOTPSetup, error) {
	const op = "setupTotp"
	if err := required(op, "accessToken", accessToken); err != nil {
		return nil, err
	}
	owner, name, err := tokenUser(op, accessToken)
	if err != nil {
		return nil, err
	}
	env, err := c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/mfa/setup/initiate", bearer: accessToken,
		form: url.Values{"owner": {owner}, "name": {name}, "mfaType": {mfaTOTP}}})
	if err != nil {
		return nil, err
	}
	var data struct {
		Secret        string   `json:"secret"`
		URL           string   `json:"url"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	decodeData(env, &data)
	if data.Secret == "" {
		return nil, validationError(op, "Casdoor returned no TOTP secret")
	}
	return &TOTPSetup{Secret: data.Secret, URL: data.URL, RecoveryCodes: data.RecoveryCodes}, nil
}

// VerifyTOTP verifies the first code, then enables TOTP (Casdoor's enable call
// does not check the code itself).
func (c *Client) VerifyTOTP(ctx context.Context, in VerifyTOTPInput) error {
	const op = "verifyTotp"
	if err := required(op, "accessToken", in.AccessToken, "secret", in.Secret, "code", in.Code, "recoveryCode", in.RecoveryCode); err != nil {
		return err
	}
	owner, name, err := tokenUser(op, in.AccessToken)
	if err != nil {
		return err
	}
	if _, err := c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/mfa/setup/verify", bearer: in.AccessToken,
		form: url.Values{"owner": {owner}, "name": {name}, "mfaType": {mfaTOTP}, "passcode": {in.Code}, "secret": {in.Secret}}}); err != nil {
		return err
	}
	_, err = c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/mfa/setup/enable", bearer: in.AccessToken,
		form: url.Values{"owner": {owner}, "name": {name}, "mfaType": {mfaTOTP}, "secret": {in.Secret}, "recoveryCodes": {in.RecoveryCode}}})
	return err
}
