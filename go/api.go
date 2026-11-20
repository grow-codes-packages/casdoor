package casdoor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// cookieJar is a minimal cookie jar for one Casdoor origin.
type cookieJar struct {
	mu      sync.Mutex
	cookies map[string]string
	order   []string
}

func newCookieJar() *cookieJar { return &cookieJar{cookies: map[string]string{}} }

func (j *cookieJar) header() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	parts := make([]string, 0, len(j.order))
	for _, k := range j.order {
		parts = append(parts, k+"="+j.cookies[k])
	}
	return strings.Join(parts, "; ")
}

func (j *cookieJar) absorb(h http.Header) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, raw := range h.Values("Set-Cookie") {
		pair, _, _ := strings.Cut(raw, ";")
		name, value, ok := strings.Cut(pair, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		if _, seen := j.cookies[name]; !seen {
			j.order = append(j.order, name)
		}
		j.cookies[name] = strings.TrimSpace(value)
	}
}

func (j *cookieJar) clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = map[string]string{}
	j.order = nil
}

// envelope is the Casdoor response envelope.
type envelope struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Code   string          `json:"code"`
	Data   json.RawMessage `json:"data"`
	Data2  json.RawMessage `json:"data2"`
}

// authMode selects how a call authenticates.
type authMode int

const (
	authNone   authMode = iota
	authAdmin           // admin session when AdminPassword is set, else client credentials
	authClient          // HTTP Basic client credentials
)

// apiCall is one envelope call.
type apiCall struct {
	op     string
	method string
	path   string
	query  url.Values
	json   any
	form   url.Values
	auth   authMode
	bearer string
	jar    *cookieJar
}

// api holds the Casdoor call helpers shared by the flows and admin operations.
type api struct {
	cfg       Config
	t         *httpTransport
	adminMu   sync.Mutex
	adminJar  *cookieJar
	adminDone bool
}

func newAPI(cfg Config, t *httpTransport) *api {
	a := &api{cfg: cfg, t: t, adminJar: newCookieJar()}
	t.setErrorMapper(a.mapHTTPError)
	return a
}

// mapHTTPError maps envelopes and OAuth bodies of non-2xx responses.
func (a *api) mapHTTPError(res *response, err *Error) *Error {
	var body map[string]any
	if json.Unmarshal(res.Body, &body) != nil {
		return err // not JSON: keep the canonical error
	}
	op, _, _ := strings.Cut(err.Message, ":")
	if code, ok := body["error"].(string); ok && code != "" {
		desc, _ := body["error_description"].(string)
		return oauthError(op, code, a.t.redact(desc), res.Status)
	}
	if body["status"] == "error" {
		msg, _ := body["msg"].(string)
		return envelopeError(op, a.t.redact(msg), "", res.Status)
	}
	return nil
}

func (a *api) organization(op, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if a.cfg.Organization == "" {
		return "", configError(op, "organization is not configured")
	}
	return a.cfg.Organization, nil
}

func (a *api) application(op, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	if a.cfg.Application == "" {
		return "", configError(op, "application is not configured")
	}
	return a.cfg.Application, nil
}

func (a *api) clientID(op string) (string, error) {
	if a.cfg.ClientID == "" {
		return "", configError(op, "client id is not configured")
	}
	return a.cfg.ClientID, nil
}

// call sends an envelope call and returns the status-ok envelope.
func (a *api) call(ctx context.Context, c apiCall) (*envelope, error) {
	if c.auth == authAdmin && !a.cfg.AdminPassword.IsZero() {
		if err := a.ensureAdmin(ctx, c.op); err != nil {
			return nil, err
		}
		viaSession := c
		viaSession.auth = authNone
		viaSession.jar = a.adminJar
		env, err := a.send(ctx, viaSession)
		if ReasonOf(err) != ReasonLoginRequired {
			return env, err
		}
		a.adminMu.Lock()
		a.adminDone = false
		a.adminMu.Unlock()
		if err := a.ensureAdmin(ctx, c.op); err != nil {
			return nil, err
		}
		return a.send(ctx, viaSession)
	}
	return a.send(ctx, c)
}

func (a *api) send(ctx context.Context, c apiCall) (*envelope, error) {
	h := http.Header{}
	if c.auth == authAdmin || c.auth == authClient {
		id, err := a.clientID(c.op)
		if err != nil {
			return nil, err
		}
		if a.cfg.ClientSecret.IsZero() {
			return nil, configError(c.op, "client secret is not configured")
		}
		h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+a.cfg.ClientSecret.Reveal())))
	}
	if c.bearer != "" {
		h.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.jar != nil {
		if cookie := c.jar.header(); cookie != "" {
			h.Set("Cookie", cookie)
		}
	}
	req := &request{Method: c.method, Path: c.path, Query: c.query, Header: h, Operation: c.op}
	if c.json != nil {
		req.JSON = c.json
	} else if c.form != nil {
		req.Body = []byte(c.form.Encode())
		req.ContentType = "application/x-www-form-urlencoded"
	}
	if req.Method == "" {
		req.Method = http.MethodGet
		if req.Body != nil || req.JSON != nil {
			req.Method = http.MethodPost
		}
	}
	res, err := a.t.do(ctx, req)
	if err != nil {
		return nil, err
	}
	if c.jar != nil {
		c.jar.absorb(res.Header)
	}
	var env envelope
	if len(res.Body) > 0 && json.Unmarshal(res.Body, &env) != nil {
		return nil, &Error{Code: ErrorCodeUnavailable, Message: c.op + ": invalid JSON response", HTTPStatus: res.Status}
	}
	if env.Status == "error" {
		return nil, envelopeError(c.op, a.t.redact(env.Msg), env.Code, res.Status)
	}
	return &env, nil
}

// oauth posts a form to a token endpoint and returns the JSON body.
func (a *api) oauth(ctx context.Context, op, path string, form url.Values) (map[string]any, error) {
	res, err := a.t.do(ctx, &request{
		Method: http.MethodPost, Path: path, Operation: op,
		Body: []byte(form.Encode()), ContentType: "application/x-www-form-urlencoded",
	})
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if json.Unmarshal(res.Body, &body) != nil {
		return nil, &Error{Code: ErrorCodeUnavailable, Message: op + ": invalid JSON response", HTTPStatus: res.Status}
	}
	if code, ok := body["error"].(string); ok && code != "" {
		desc, _ := body["error_description"].(string)
		return nil, oauthError(op, code, a.t.redact(desc), res.Status)
	}
	if body["status"] == "error" {
		msg, _ := body["msg"].(string)
		return nil, envelopeError(op, a.t.redact(msg), "", res.Status)
	}
	return body, nil
}

func (a *api) ensureAdmin(ctx context.Context, op string) error {
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	if a.adminDone {
		return nil
	}
	a.adminJar.clear()
	_, err := a.send(ctx, apiCall{
		op: op + " (admin sign-in)", method: http.MethodPost, path: "/api/login", jar: a.adminJar,
		json: map[string]any{
			"application": a.cfg.AdminApplication, "organization": a.cfg.AdminOrganization,
			"username": a.cfg.AdminUsername, "password": a.cfg.AdminPassword.Reveal(),
			"type": "login", "signinMethod": "Password", "autoSignin": false,
		},
	})
	if err != nil {
		return err
	}
	if a.adminJar.header() == "" {
		return configError(op, "Casdoor returned no session cookie for the admin sign-in")
	}
	a.adminDone = true
	return nil
}

// decodeData decodes env.Data into out; "null" leaves out untouched and reports false.
func decodeData(env *envelope, out any) bool {
	if env == nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return false
	}
	return json.Unmarshal(env.Data, out) == nil
}

// jsonUnmarshal decodes b into v; an empty body is not an error.
func jsonUnmarshal(b []byte, v any) error {
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, v)
}
