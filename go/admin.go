package casdoor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Admin operations are idempotent. Casdoor quirks encoded here: ids are always
// owner/name (applications, organizations and providers are owned by "admin",
// roles and users by the organization); updates replace the WHOLE object (read,
// change, send back); objects read without admin rights carry "***" and are never
// written back; user names cannot be e-mail addresses.

const mask = "***"

type obj = map[string]any

func (c *Client) getObject(ctx context.Context, op, kind, id string) (obj, error) {
	env, err := c.api.call(ctx, apiCall{op: op, path: "/api/get-" + kind, query: url.Values{"id": {id}}, auth: authAdmin})
	if err != nil {
		return nil, err
	}
	var o obj
	if !decodeData(env, &o) {
		return nil, nil
	}
	return o, nil
}

func (c *Client) addObject(ctx context.Context, op, kind string, body obj) error {
	_, err := c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/add-" + kind, json: body, auth: authAdmin})
	return err
}

// updateObject sends the whole object; any field still masked (except exempt)
// would be stored as "***", so the update is refused.
func (c *Client) updateObject(ctx context.Context, op, kind, id string, body obj, exempt ...string) error {
	for k, v := range body {
		if v == mask && !slices.Contains(exempt, k) {
			return maskedObjectError(op, kind)
		}
	}
	_, err := c.api.call(ctx, apiCall{op: op, method: http.MethodPost, path: "/api/update-" + kind,
		query: url.Values{"id": {id}}, json: body, auth: authAdmin})
	return err
}

func differs(current, patch obj) bool {
	for k, v := range patch {
		a, _ := json.Marshal(current[k])
		b, _ := json.Marshal(v)
		if string(a) != string(b) {
			return true
		}
	}
	return false
}

func merge(current, patch obj) obj {
	out := obj{}
	for k, v := range current {
		out[k] = v
	}
	for k, v := range patch {
		out[k] = v
	}
	return out
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EnsureOrganization creates the organization unless it exists, then aligns its
// password rules and TOTP offer. It reports whether it was created.
func (c *Client) EnsureOrganization(ctx context.Context, in EnsureOrganizationInput) (bool, error) {
	const op = "ensureOrganization"
	if err := required(op, "name", in.Name); err != nil {
		return false, err
	}
	display := in.DisplayName
	if display == "" {
		display = in.Name
	}
	opts := in.PasswordOptions
	if len(opts) == 0 {
		opts = []string{"AtLeast8"}
	}
	mfa := []any{obj{"name": "app", "rule": "Optional"}}
	if in.DisableTOTP {
		mfa = []any{}
	}
	patch := obj{"displayName": display, "passwordOptions": opts, "mfaItems": mfa}
	id := "admin/" + in.Name
	cur, err := c.getObject(ctx, op, "organization", id)
	if err != nil {
		return false, err
	}
	created := false
	if cur == nil {
		body := merge(obj{"owner": "admin", "name": in.Name, "passwordType": "bcrypt", "countryCodes": []string{"US"},
			"languages": []string{"en"}, "defaultAvatar": ""}, patch)
		if err := c.addObject(ctx, op, "organization", body); err != nil {
			return false, err
		}
		created = true
		if cur, err = c.getObject(ctx, op, "organization", id); err != nil {
			return false, err
		}
	}
	if cur != nil && differs(cur, patch) {
		if err := c.updateObject(ctx, op, "organization", id, merge(cur, patch)); err != nil {
			return false, err
		}
	}
	return created, nil
}

func providerRef(name string) obj {
	return obj{"owner": "", "name": name, "canSignUp": true, "canSignIn": true, "canUnlink": true, "prompted": false, "rule": "All"}
}

func intOr(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// EnsureApplication creates or aligns the OAuth application (exact redirect
// URIs, JWT tokens, password sign-in, lockout, pinned client credentials) and
// returns its client credentials.
func (c *Client) EnsureApplication(ctx context.Context, in EnsureApplicationInput) (*ApplicationInfo, error) {
	const op = "ensureApplication"
	name, err := c.api.application(op, in.Name)
	if err != nil {
		return nil, err
	}
	org, err := c.api.organization(op, in.Organization)
	if err != nil {
		return nil, err
	}
	emailRule := "No verification"
	if in.SignUpEmailCode {
		emailRule = "Normal"
	}
	item := func(n string, visible, req bool, rule string) obj {
		return obj{"name": n, "visible": visible, "required": req, "prompted": false, "rule": rule}
	}
	grants := in.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	redirects := in.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	display := in.DisplayName
	if display == "" {
		display = name
	}
	cert := in.Cert
	if cert == "" {
		cert = "cert-built-in"
	}
	patch := obj{
		"organization": org, "displayName": display, "redirectUris": redirects, "grantTypes": grants,
		"enablePassword": true, "enableSignUp": !in.DisableSignUp,
		"signinMethods": []any{obj{"name": "Password", "displayName": "Password", "rule": "All"}},
		"signupItems": []any{item("ID", false, true, "Random"), item("Username", true, true, "None"),
			item("Display name", true, false, "None"), item("Password", true, true, "None"),
			item("Confirm password", true, true, "None"), item("Email", true, true, emailRule),
			item("Agreement", false, false, "None")},
		"tokenFormat": "JWT", "cert": cert,
		"expireInHours": intOr(in.ExpireInHours, 1), "refreshExpireInHours": intOr(in.RefreshExpireInHours, 168),
		"failedSigninLimit": intOr(in.FailedSigninLimit, 5), "failedSigninFrozenTime": intOr(in.FailedSigninFrozenTime, 15),
	}
	clientID := in.ClientID
	if clientID == "" {
		clientID = c.cfg.ClientID
	}
	secret := in.ClientSecret.Reveal()
	if secret == "" {
		secret = c.cfg.ClientSecret.Reveal()
	}
	if clientID != "" {
		patch["clientId"] = clientID
	}
	if secret != "" {
		patch["clientSecret"] = secret
	}
	id := "admin/" + name
	cur, err := c.getObject(ctx, op, "application", id)
	if err != nil {
		return nil, err
	}
	created := false
	if cur == nil {
		body := merge(obj{"owner": "admin", "name": name, "clientId": randomHex(10), "clientSecret": randomHex(20)}, patch)
		if err := c.addObject(ctx, op, "application", body); err != nil {
			return nil, err
		}
		created = true
		if cur, err = c.getObject(ctx, op, "application", id); err != nil {
			return nil, err
		}
		if cur == nil {
			return nil, validationError(op, "application "+name+" was not created")
		}
	}
	existing, _ := cur["providers"].([]any)
	providers := slices.Clone(existing)
	for _, p := range in.Providers {
		if !hasNamed(providers, p) {
			providers = append(providers, providerRef(p))
		}
	}
	if len(providers) != len(existing) {
		patch["providers"] = providers
	}
	if differs(cur, patch) {
		cur = merge(cur, patch)
		if err := c.updateObject(ctx, op, "application", id, cur); err != nil {
			return nil, err
		}
	}
	if cur["clientSecret"] == mask {
		return nil, maskedObjectError(op, "application")
	}
	info := &ApplicationInfo{Name: name, Organization: org, Created: created}
	info.ClientID, _ = cur["clientId"].(string)
	s, _ := cur["clientSecret"].(string)
	info.ClientSecret = NewSecret(s)
	info.RedirectURIs = stringList(cur["redirectUris"])
	return info, nil
}

func hasNamed(list []any, name string) bool {
	for _, p := range list {
		if m, ok := p.(map[string]any); ok && m["name"] == name {
			return true
		}
	}
	return false
}

func stringList(v any) []string {
	out := []string{}
	switch l := v.(type) {
	case []any:
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, l...)
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// EnsureEmailProvider creates or aligns an SMTP e-mail provider and lists it on
// the configured application when that application exists. It reports whether
// the provider was created.
func (c *Client) EnsureEmailProvider(ctx context.Context, s SMTPSettings) (bool, error) {
	const op = "ensureEmailProvider"
	if err := required(op, "host", s.Host, "from", s.From); err != nil {
		return false, err
	}
	if s.Port <= 0 {
		return false, validationError(op, "port must be a positive integer")
	}
	name := orDefault(s.Name, "provider-email")
	patch := obj{"displayName": name, "category": "Email", "type": "Default", "host": s.Host, "port": s.Port,
		"disableSsl": s.DisableSSL,
		// Casdoor: clientId/clientSecret = SMTP login, clientId2/clientSecret2 = from address/name.
		"clientId": orDefault(s.Username, s.From), "clientId2": s.From, "clientSecret2": orDefault(s.FromName, "Casdoor"),
		"title": orDefault(s.Title, "Verification code"), "content": orDefault(s.Content, "Your verification code is %s")}
	if !s.Password.IsZero() {
		patch["clientSecret"] = s.Password.Reveal()
	}
	id := "admin/" + name
	cur, err := c.getObject(ctx, op, "provider", id)
	if err != nil {
		return false, err
	}
	created := false
	if cur == nil {
		if err := c.addObject(ctx, op, "provider", merge(obj{"owner": "admin", "name": name, "clientSecret": ""}, patch)); err != nil {
			return false, err
		}
		created = true
	} else if differs(cur, patch) {
		if err := c.updateObject(ctx, op, "provider", id, merge(cur, patch)); err != nil {
			return false, err
		}
	}
	if c.cfg.Application != "" {
		appID := "admin/" + c.cfg.Application
		app, err := c.getObject(ctx, op, "application", appID)
		if err != nil {
			return false, err
		}
		if app != nil {
			providers, _ := app["providers"].([]any)
			if !hasNamed(providers, name) {
				app["providers"] = append(slices.Clone(providers), providerRef(name))
				if err := c.updateObject(ctx, op, "application", appID, app); err != nil {
					return false, err
				}
			}
		}
	}
	return created, nil
}

// EnsureRoles creates every missing role (organization "" = config Organization).
func (c *Client) EnsureRoles(ctx context.Context, names []string, organization string) ([]RoleInfo, error) {
	const op = "ensureRoles"
	owner, err := c.api.organization(op, organization)
	if err != nil {
		return nil, err
	}
	out := make([]RoleInfo, 0, len(names))
	for _, n := range names {
		if err := required(op, "role", n); err != nil {
			return nil, err
		}
		cur, err := c.getObject(ctx, op, "role", owner+"/"+n)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			if err := c.addObject(ctx, op, "role", obj{"owner": owner, "name": n, "displayName": n, "users": []string{},
				"groups": []string{}, "roles": []string{}, "domains": []string{}, "isEnabled": true}); err != nil {
				return nil, err
			}
		}
		out = append(out, RoleInfo{Name: n, Created: cur == nil})
	}
	return out, nil
}

func (c *Client) findUser(ctx context.Context, op, owner, user string) (obj, error) {
	if strings.Contains(user, "@") {
		env, err := c.api.call(ctx, apiCall{op: op, path: "/api/get-user", query: url.Values{"owner": {owner}, "email": {user}}, auth: authAdmin})
		if err != nil {
			return nil, err
		}
		var o obj
		if !decodeData(env, &o) {
			return nil, nil
		}
		return o, nil
	}
	id := user
	if !strings.Contains(user, "/") {
		id = owner + "/" + user
	}
	return c.getObject(ctx, op, "user", id)
}

func toUser(owner string, u obj, created bool) *User {
	str := func(k string) string { s, _ := u[k].(string); return s }
	return &User{UserID: owner + "/" + str("name"), Organization: owner, Name: str("name"), ID: str("id"),
		Email: str("email"), DisplayName: str("displayName"), EmailVerified: u["emailVerified"] == true,
		IsForbidden: u["isForbidden"] == true, Created: created}
}

// EnsureUser creates or aligns a user (verified e-mail unless Unverified,
// password, display name) and assigns its roles.
func (c *Client) EnsureUser(ctx context.Context, in EnsureUserInput) (*User, error) {
	const op = "ensureUser"
	if err := required(op, "email", in.Email); err != nil {
		return nil, err
	}
	owner, err := c.api.organization(op, in.Organization)
	if err != nil {
		return nil, err
	}
	name := userNameFor(in.Email, in.Username)
	u, err := c.findUser(ctx, op, owner, in.Email)
	if err != nil {
		return nil, err
	}
	created := false
	if u == nil {
		if in.Password.IsZero() {
			return nil, validationError(op, "password is required to create a user")
		}
		body := obj{"owner": owner, "name": name, "email": in.Email, "password": in.Password.Reveal(),
			"displayName": orDefault(in.DisplayName, name), "type": "normal-user", "emailVerified": !in.Unverified}
		if c.cfg.Application != "" {
			body["signupApplication"] = c.cfg.Application
		}
		if err := c.addObject(ctx, op, "user", body); err != nil {
			return nil, err
		}
		created = true
		if u, err = c.findUser(ctx, op, owner, owner+"/"+name); err != nil {
			return nil, err
		}
		if u == nil {
			return nil, validationError(op, "user "+name+" was not created")
		}
	} else {
		patch := obj{"emailVerified": !in.Unverified}
		if in.DisplayName != "" {
			patch["displayName"] = in.DisplayName
		}
		if !in.Password.IsZero() {
			patch["password"] = in.Password.Reveal()
		}
		if !in.Password.IsZero() || differs(u, patch) {
			u = merge(u, patch)
			n, _ := u["name"].(string)
			if err := c.updateObject(ctx, op, "user", owner+"/"+n, u, "password"); err != nil {
				return nil, err
			}
		}
	}
	if len(in.Roles) > 0 {
		n, _ := u["name"].(string)
		if err := c.AssignRoles(ctx, owner+"/"+n, in.Roles, owner); err != nil {
			return nil, err
		}
	}
	return toUser(owner, u, created), nil
}

// AssignRoles adds a user ("org/name", name or e-mail) to roles, creating
// missing roles (organization "" = config Organization).
func (c *Client) AssignRoles(ctx context.Context, user string, roles []string, organization string) error {
	const op = "assignRoles"
	if err := required(op, "user", user); err != nil {
		return err
	}
	owner, err := c.api.organization(op, organization)
	if err != nil {
		return err
	}
	u, err := c.findUser(ctx, op, owner, user)
	if err != nil {
		return err
	}
	if u == nil {
		return NewError(ErrorCodeNotFound, op+": user not found", nil)
	}
	uOwner, _ := u["owner"].(string)
	uName, _ := u["name"].(string)
	userID := orDefault(uOwner, owner) + "/" + uName
	if _, err := c.EnsureRoles(ctx, roles, owner); err != nil {
		return err
	}
	for _, r := range roles {
		id := owner + "/" + r
		cur, err := c.getObject(ctx, op, "role", id)
		if err != nil {
			return err
		}
		if cur == nil {
			continue
		}
		users := stringList(cur["users"])
		if slices.Contains(users, userID) {
			continue
		}
		cur["users"] = append(users, userID)
		if err := c.updateObject(ctx, op, "role", id, cur); err != nil {
			return err
		}
	}
	return nil
}
