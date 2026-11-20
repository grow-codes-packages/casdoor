package casdoor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PKCE is a code verifier and its S256 challenge (RFC 7636).
type PKCE struct {
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewPKCE returns a new verifier (64 characters) and its S256 challenge.
func NewPKCE() PKCE {
	v := randomURLSafe(48)
	return PKCE{CodeVerifier: v, CodeChallenge: PKCEChallenge(v), CodeChallengeMethod: "S256"}
}

// PKCEChallenge returns base64url(sha256(verifier)).
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomState returns a random URL-safe value for state or nonce.
func RandomState() string { return randomURLSafe(24) }

// TOTPCode returns the TOTP code (RFC 6238, SHA-1, 6 digits, 30 s) of a base32
// secret at t; for tests and e2e helpers.
func TOTPCode(secret string, t time.Time) (string, error) {
	clean := strings.ToUpper(strings.TrimRight(strings.Join(strings.Fields(secret), ""), "="))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return "", validationError("totpCode", "invalid base32 TOTP secret")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30)) //nolint:gosec // time is positive
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}

// decodeJWTPayload returns the payload of a JWT without verifying it (only for
// tokens Casdoor just issued).
func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 || parts[1] == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

var (
	reUserName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$`)
	reNameChars = regexp.MustCompile(`[^A-Za-z0-9_-]+`)
)

// userNameFor returns a Casdoor user name: username when valid, else derived from the e-mail.
func userNameFor(email, username string) string {
	if username != "" && reUserName.MatchString(username) {
		return username
	}
	base := username
	if base == "" {
		base, _, _ = strings.Cut(email, "@")
	}
	base = strings.Trim(reNameChars.ReplaceAllString(base, "-"), "-_")
	if len(base) > 39 {
		base = base[:39]
	}
	if base == "" {
		return "user"
	}
	return base
}
