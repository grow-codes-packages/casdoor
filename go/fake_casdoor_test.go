package casdoor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCasdoor is a stateful fake reproducing the Casdoor quirks the client
// handles: HTTP 200 + {"status":"error"}, "Phone number is invalid" for empty
// passwords, masked "***" secrets for non-admins, full-object updates, cookie
// sessions, PKCE, NextMfa and one code per address per 60 s.
type fakeCasdoor struct {
	mu        sync.Mutex
	srv       *httptest.Server
	orgs      map[string]obj
	apps      map[string]obj
	providers map[string]obj
	roles     map[string]obj
	users     map[string]obj
	mails     map[string]string
	mailTimes map[string]time.Time
	sessions  map[string]obj
	access    map[string]string
	refresh   map[string]string
	codes     map[string]obj
	calls     []string
	seq       int
}

const fakeAdminPassword = "admin-pass-123"

func newFake(t *testing.T) *fakeCasdoor {
	t.Helper()
	f := &fakeCasdoor{
		orgs: map[string]obj{"admin/acme": {"owner": "admin", "name": "acme", "mfaItems": []any{}}},
		apps: map[string]obj{"admin/app-acme": {"owner": "admin", "name": "app-acme", "organization": "acme",
			"clientId": "cid", "clientSecret": "csecret", "cert": "cert-built-in", "providers": []any{}}},
		providers: map[string]obj{}, roles: map[string]obj{}, users: map[string]obj{}, mails: map[string]string{},
		mailTimes: map[string]time.Time{}, sessions: map[string]obj{}, access: map[string]string{},
		refresh: map[string]string{}, codes: map[string]obj{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCasdoor) next(p string) string { f.seq++; return fmt.Sprintf("%s%d", p, f.seq) }

func b64json(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }

func (f *fakeCasdoor) issue(userID string) obj {
	u := f.users[userID]
	var roles []any
	for _, r := range f.roles {
		for _, x := range stringList(r["users"]) {
			if x == userID {
				roles = append(roles, obj{"name": r["name"]})
			}
		}
	}
	payload := obj{"owner": u["owner"], "name": u["name"], "email": u["email"], "email_verified": u["emailVerified"] == true, "roles": roles}
	at := b64json(obj{"alg": "RS256"}) + "." + b64json(payload) + "." + f.next("sig")
	rt := f.next("rt")
	f.access[at], f.refresh[rt] = userID, userID
	return obj{"access_token": at, "refresh_token": rt, "id_token": at, "token_type": "Bearer", "expires_in": 3600, "scope": "openid"}
}

func (f *fakeCasdoor) findUser(owner, key string) obj {
	for _, u := range f.users {
		if u["owner"] == owner && (u["name"] == key || u["email"] == key) {
			return u
		}
	}
	return nil
}

func okEnv(data any, data2 ...any) (int, any) {
	b := obj{"status": "ok", "msg": "", "data": data}
	if len(data2) > 0 {
		b["data2"] = data2[0]
	}
	return 200, b
}

func failEnv(msg string, code ...string) (int, any) {
	b := obj{"status": "error", "msg": msg, "data": nil}
	if len(code) > 0 {
		b["code"] = code[0]
	}
	return 200, b
}

func (f *fakeCasdoor) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	f.calls = append(f.calls, r.URL.Path)
	var sess obj
	if ck, err := r.Cookie("casdoor_session_id"); err == nil && f.sessions[ck.Value] != nil {
		sess = f.sessions[ck.Value]
	} else {
		sid := f.next("sess")
		sess = obj{}
		f.sessions[sid] = sess
		w.Header().Add("Set-Cookie", "casdoor_session_id="+sid+"; Path=/; HttpOnly")
	}
	status, body := f.route(r, raw, sess)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if s, ok := body.(string); ok {
		_, _ = w.Write([]byte(s))
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeCasdoor) who(r *http.Request, sess obj) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		b, _ := base64.StdEncoding.DecodeString(auth[6:])
		id, secret, _ := strings.Cut(string(b), ":")
		for _, a := range f.apps {
			if a["clientId"] == id && a["clientSecret"] == secret {
				return "app"
			}
		}
		return "bad"
	}
	if strings.HasPrefix(auth, "Bearer ") {
		if u, ok := f.access[auth[7:]]; ok {
			return u
		}
		return "expired"
	}
	u, _ := sess["user"].(string)
	return u
}

var reCRUD = regexp.MustCompile(`^/api/(get|add|update)-(organization|application|provider|role|user)$`)

func (f *fakeCasdoor) route(r *http.Request, raw []byte, sess obj) (int, any) {
	who := f.who(r, sess)
	admin := who == "admin" || who == "app"
	if who == "bad" {
		return failEnv("Please login first")
	}
	if who == "expired" {
		return 401, obj{"status": "error", "msg": "Access token has expired"}
	}
	q := r.URL.Query()
	var body obj
	form := url.Values{}
	if strings.HasPrefix(string(raw), "{") {
		_ = json.Unmarshal(raw, &body)
	} else {
		form, _ = url.ParseQuery(string(raw))
	}
	str := func(k string) string { s, _ := body[k].(string); return s }
	switch p := r.URL.Path; {
	case p == "/api/health":
		return okEnv(nil)
	case p == "/api/get-version-info":
		if who == "admin" {
			return okEnv(obj{"version": "v4.27.1"})
		}
		return failEnv("Unauthorized operation")
	case p == "/api/login":
		return f.login(q, body, sess)
	case p == "/api/login/oauth/access_token":
		var app obj
		for _, a := range f.apps {
			if a["clientId"] == form.Get("client_id") {
				app = a
			}
		}
		if app == nil || app["clientSecret"] != form.Get("client_secret") {
			return 400, obj{"error": "invalid_client", "error_description": "client_secret is invalid"}
		}
		e := f.codes[form.Get("code")]
		delete(f.codes, form.Get("code"))
		if e == nil {
			return 400, obj{"error": "invalid_grant", "error_description": "authorization code is invalid"}
		}
		if PKCEChallenge(form.Get("code_verifier")) != e["challenge"] {
			return 400, obj{"error": "invalid_grant", "error_description": "code_verifier is invalid"}
		}
		return 200, f.issue(e["user"].(string))
	case p == "/api/login/oauth/refresh_token":
		u, ok := f.refresh[form.Get("refresh_token")]
		if !ok {
			return 400, obj{"error": "invalid_grant", "error_description": "refresh token is invalid or revoked"}
		}
		delete(f.refresh, form.Get("refresh_token"))
		return 200, f.issue(u)
	case p == "/api/logout":
		tok := q.Get("id_token_hint")
		if _, ok := f.access[tok]; !ok {
			return 401, obj{"status": "error", "msg": "Access token has expired"}
		}
		delete(f.access, tok)
		return okEnv(nil)
	case p == "/api/signup":
		if str("password") == "" {
			return failEnv("Phone number is invalid in your region US")
		}
		app := f.apps["admin/"+str("application")]
		needs := false
		items, _ := app["signupItems"].([]any)
		for _, it := range items {
			if m, _ := it.(map[string]any); m["name"] == "Email" && m["rule"] == "Normal" {
				needs = true
			}
		}
		if f.findUser(str("organization"), str("username")) != nil {
			return failEnv("The username already exists")
		}
		if needs && str("emailCode") != f.mails[str("email")] {
			return failEnv("password or code is incorrect, you have 4 remaining chances")
		}
		id := str("organization") + "/" + str("username")
		f.users[id] = obj{"owner": str("organization"), "name": str("username"), "email": str("email"),
			"password": str("password"), "emailVerified": needs}
		return okEnv(id)
	case p == "/api/send-verification-code":
		dest := form.Get("dest")
		if t, ok := f.mailTimes[dest]; ok && time.Since(t) < time.Minute {
			return failEnv("you can only send one code in 60s")
		}
		owner, _ := f.apps[form.Get("applicationId")]["organization"].(string)
		m := form.Get("method")
		if (m == "login" || m == "forget") && f.findUser(owner, dest) == nil {
			return failEnv("the user does not exist, please sign up first")
		}
		if m == "signup" && f.findUser(owner, dest) != nil {
			return failEnv("Email already exists")
		}
		f.mails[dest] = fmt.Sprint(100000 + f.seq)
		f.seq++
		f.mailTimes[dest] = time.Now()
		return okEnv(nil)
	case p == "/api/verify-code":
		if str("code") == "" {
			return failEnv("Phone number is invalid in your region US")
		}
		if f.mails[str("username")] != str("code") {
			return failEnv("password or code is incorrect, you have 4 remaining chances")
		}
		sess["verifiedCode"] = str("code")
		return okEnv(nil)
	case p == "/api/set-password":
		if form.Get("code") == "" || sess["verifiedCode"] != form.Get("code") {
			return failEnv("Please login first")
		}
		u := f.users[form.Get("userOwner")+"/"+form.Get("userName")]
		u["password"] = form.Get("newPassword")
		return okEnv(nil)
	case strings.HasPrefix(p, "/api/mfa/setup/"):
		return f.mfa(p, form, who)
	case reCRUD.MatchString(p):
		m := reCRUD.FindStringSubmatch(p)
		return f.crud(m[1], m[2], q, body, admin)
	}
	return 404, "not found"
}

func (f *fakeCasdoor) code(q url.Values, u obj) (int, any) {
	code := f.next("code")
	f.codes[code] = obj{"user": fmt.Sprint(u["owner"], "/", u["name"]), "challenge": q.Get("code_challenge")}
	return okEnv(code)
}

func (f *fakeCasdoor) login(q url.Values, body obj, sess obj) (int, any) {
	str := func(k string) string { s, _ := body[k].(string); return s }
	if _, hasPassword := body["password"]; !hasPassword {
		if uid, ok := sess["mfaUser"].(string); ok {
			u := f.users[uid]
			code, _ := TOTPCode(u["totpSecret"].(string), time.Now())
			passOK := str("passcode") != "" && str("passcode") == code
			recOK := str("recoveryCode") != "" && str("recoveryCode") == u["recoveryCode"]
			if !passOK && !recOK {
				return failEnv("totp passcode error, password or code is incorrect, you have 4 remaining chances", "mfa-failed")
			}
			delete(sess, "mfaUser")
			return f.code(q, u)
		}
	}
	if str("password") == "" {
		return failEnv("Phone number is invalid in your region US")
	}
	if q.Get("clientId") == "" {
		if str("username") == "admin" && str("password") == fakeAdminPassword {
			sess["user"] = "admin"
			return okEnv("built-in/admin")
		}
		return failEnv("password or code is incorrect, you have 4 remaining chances", "wrong-password")
	}
	u := f.findUser(str("organization"), str("username"))
	if u == nil {
		return failEnv("The user: acme/" + str("username") + " doesn't exist")
	}
	if u["password"] != str("password") {
		return failEnv("password or code is incorrect, you have 4 remaining chances", "wrong-password")
	}
	if secret, _ := u["totpSecret"].(string); secret != "" {
		sess["mfaUser"] = fmt.Sprint(u["owner"], "/", u["name"]) // a passcode here is ignored
		return okEnv("NextMfa", []any{obj{"enabled": true, "mfaType": "app"}})
	}
	return f.code(q, u)
}

func (f *fakeCasdoor) mfa(p string, form url.Values, who string) (int, any) {
	uid := form.Get("owner") + "/" + form.Get("name")
	if who != uid {
		return failEnv("Unauthorized operation")
	}
	u := f.users[uid]
	org := f.orgs["admin/"+u["owner"].(string)]
	allowed := false
	items, _ := org["mfaItems"].([]any)
	for _, it := range items {
		if m, _ := it.(map[string]any); m["name"] == "app" {
			allowed = true
		}
	}
	if !allowed {
		return failEnv("the MFA type: app is not allowed by the MFA items")
	}
	if strings.HasSuffix(p, "/initiate") {
		return okEnv(obj{"secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "url": "otpauth://totp/x", "recoveryCodes": []string{"rc-1"}})
	}
	if form.Get("secret") == "" {
		return failEnv("totp secret is missing")
	}
	if strings.HasSuffix(p, "/verify") {
		code, _ := TOTPCode(form.Get("secret"), time.Now())
		if form.Get("passcode") != code {
			return failEnv("passcode is invalid")
		}
		return okEnv("OK")
	}
	u["totpSecret"], u["recoveryCode"] = form.Get("secret"), form.Get("recoveryCodes")
	return okEnv("OK")
}

func (f *fakeCasdoor) crud(verb, kind string, q url.Values, body obj, admin bool) (int, any) {
	store := map[string]map[string]obj{"organization": f.orgs, "application": f.apps, "provider": f.providers, "role": f.roles, "user": f.users}[kind]
	copyObj := func(o obj, masked ...string) obj {
		out := merge(o, nil)
		for _, k := range masked {
			out[k] = mask
		}
		return out
	}
	if verb == "get" {
		if kind == "application" || kind == "organization" {
			o := store[q.Get("id")]
			if o == nil {
				return okEnv(nil)
			}
			if admin {
				return okEnv(o)
			}
			return okEnv(copyObj(o, "clientSecret", "cert"))
		}
		if !admin {
			return failEnv("Please login first")
		}
		if kind == "user" && q.Has("email") {
			u := f.findUser(q.Get("owner"), q.Get("email"))
			if u == nil {
				return okEnv(nil)
			}
			return okEnv(copyObj(u, "password"))
		}
		o := store[q.Get("id")]
		if o == nil {
			return okEnv(nil)
		}
		if kind == "user" {
			return okEnv(copyObj(o, "password"))
		}
		return okEnv(o)
	}
	if !admin {
		return failEnv("Please login first")
	}
	if verb == "add" {
		id := fmt.Sprint(body["owner"], "/", body["name"])
		if store[id] != nil {
			return failEnv(`pq: duplicate key value violates unique constraint "pkey"`)
		}
		store[id] = body
		return okEnv("Affected")
	}
	id := q.Get("id")
	cur := store[id]
	if cur == nil {
		return failEnv("The " + kind + ": " + id + " does not exist")
	}
	if kind == "user" && body["password"] == mask {
		body["password"] = cur["password"]
	}
	store[id] = body // full-object update
	return okEnv("Affected")
}

// browserCode simulates the browser leg of the code flow and returns a code.
func (f *fakeCasdoor) browserCode(t *testing.T, user, password, challenge string) string {
	t.Helper()
	b, _ := json.Marshal(obj{"organization": "acme", "username": user, "password": password})
	res, err := http.Post(f.srv.URL+"/api/login?clientId=cid&code_challenge="+challenge, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var env struct{ Data string }
	_ = json.NewDecoder(res.Body).Decode(&env)
	return env.Data
}
