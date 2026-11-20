package casdoor

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Reason values attached to normalized Casdoor errors (see ReasonOf).
const (
	ReasonEmptyCredential    = "empty_credential"
	ReasonInvalidCredentials = "invalid_credentials"
	ReasonLoginRequired      = "login_required"
	ReasonForbidden          = "forbidden"
	ReasonLocked             = "locked"
	ReasonRateLimited        = "rate_limited"
	ReasonNotFound           = "not_found"
	ReasonAlreadyExists      = "already_exists"
	ReasonNotEnabled         = "not_enabled"
	ReasonMFARequired        = "mfa_required"
	ReasonEmailNotVerified   = "email_not_verified"
	ReasonMaskedObject       = "masked_object"
	ReasonInvalidGrant       = "invalid_grant"
	ReasonInvalidClient      = "invalid_client"
	ReasonOther              = "other"
)

// CasdoorDetail is the cause (Error.Err) of every normalized Casdoor error:
// errors.As(err, &detail) gives the reason, Casdoor's own code and, for
// ReasonMFARequired, the MFA types offered.
type CasdoorDetail struct {
	Reason      string
	CasdoorCode string
	MFATypes    []string
}

// Error implements error.
func (d *CasdoorDetail) Error() string { return "casdoor: " + d.Reason }

// ReasonOf returns the Casdoor reason of err, or "".
func ReasonOf(err error) string {
	var d *CasdoorDetail
	if errors.As(err, &d) {
		return d.Reason
	}
	return ""
}

// IsMFARequired reports whether sign-in needs a TOTP code or recovery code.
func IsMFARequired(err error) bool { return ReasonOf(err) == ReasonMFARequired }

// IsEmailNotVerified reports whether the user's e-mail address is not verified.
func IsEmailNotVerified(err error) bool { return ReasonOf(err) == ReasonEmailNotVerified }

type errorRule struct {
	re     *regexp.Regexp
	code   ErrorCode
	reason string
}

var errorRules = []errorRule{
	{regexp.MustCompile(`(?i)phone number is invalid`), ErrorCodeValidation, ReasonEmptyCredential},
	{regexp.MustCompile(`(?i)remaining chances|password or code is incorrect|invalid username or password`), ErrorCodeAuthentication, ReasonInvalidCredentials},
	{regexp.MustCompile(`(?i)please (login|sign in) first|access token .*(expired|invalid)|token is invalid|invalid (access )?token`), ErrorCodeAuthentication, ReasonLoginRequired},
	{regexp.MustCompile(`(?i)too many times|wait for \d+ minutes`), ErrorCodeRateLimited, ReasonLocked},
	{regexp.MustCompile(`(?i)frozen|locked|try again later in`), ErrorCodePermissionDenied, ReasonLocked},
	{regexp.MustCompile(`(?i)only send one code in|too many|too frequent|rate limit`), ErrorCodeRateLimited, ReasonRateLimited},
	{regexp.MustCompile(`(?i)unauthorized operation|forbidden|no permission|permission denied|not allowed`), ErrorCodePermissionDenied, ReasonForbidden},
	{regexp.MustCompile(`(?i)already exist|duplicate key|already used|is used by|already been taken`), ErrorCodeConflict, ReasonAlreadyExists},
	{regexp.MustCompile(`(?i)does not exist|doesn't exist|not exist|not found|please sign up first`), ErrorCodeNotFound, ReasonNotFound},
	{regexp.MustCompile(`(?i)is not enabled|is disabled|not supported|feature is disabled`), ErrorCodeUnsupported, ReasonNotEnabled},
}

var (
	reMinutes = regexp.MustCompile(`(?i)wait for (\d+) minutes`)
	reSeconds = regexp.MustCompile(`(?i)in (\d+)\s*s`)
)

func cleanText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

func casdoorError(code ErrorCode, message string, detail *CasdoorDetail, status int) *Error {
	e := NewError(code, message, detail)
	e.HTTPStatus = status
	if code == ErrorCodeRateLimited {
		e.Retryable = false
		e.RetryAfter = 60 * time.Second
		if m := reMinutes.FindStringSubmatch(message); m != nil {
			n, _ := strconv.Atoi(m[1])
			e.RetryAfter = time.Duration(n) * time.Minute
		} else if m := reSeconds.FindStringSubmatch(message); m != nil {
			n, _ := strconv.Atoi(m[1])
			e.RetryAfter = time.Duration(n) * time.Second
		}
	}
	return e
}

// envelopeError maps a {"status":"error","msg":…} envelope (msg already redacted).
func envelopeError(op, msg, casdoorCode string, status int) *Error {
	if msg == "" {
		msg = "Casdoor returned status error"
	}
	text := cleanText(msg)
	code, reason := ErrorCodeValidation, ReasonOther
	for _, r := range errorRules {
		if r.re.MatchString(text) {
			code, reason = r.code, r.reason
			break
		}
	}
	hint := ""
	if reason == ReasonEmptyCredential {
		hint = " (Casdoor sends this for an empty password or code: check that the value was loaded)"
	}
	return casdoorError(code, op+": "+text+hint, &CasdoorDetail{Reason: reason, CasdoorCode: casdoorCode}, status)
}

var reMFA = regexp.MustCompile(`(?i)mfa enabled|multi-factor`)

// oauthError maps an OAuth {"error","error_description"} body (description already redacted).
func oauthError(op, oauthCode, description string, status int) *Error {
	text := oauthCode
	if description != "" {
		text = oauthCode + ": " + description
	}
	msg := op + ": " + cleanText(text)
	if reMFA.MatchString(description) {
		return casdoorError(ErrorCodeAuthentication, msg, &CasdoorDetail{Reason: ReasonMFARequired}, status)
	}
	switch oauthCode {
	case "invalid_grant":
		for _, r := range errorRules {
			if r.reason == ReasonLocked && r.re.MatchString(description) {
				return casdoorError(r.code, msg, &CasdoorDetail{Reason: ReasonLocked}, status)
			}
		}
		return casdoorError(ErrorCodeAuthentication, msg, &CasdoorDetail{Reason: ReasonInvalidGrant}, status)
	case "invalid_client", "unauthorized_client":
		return casdoorError(ErrorCodeAuthentication, msg, &CasdoorDetail{Reason: ReasonInvalidClient}, status)
	case "unsupported_grant_type", "unsupported_response_type":
		return casdoorError(ErrorCodeUnsupported, msg, &CasdoorDetail{Reason: ReasonNotEnabled}, status)
	default:
		return casdoorError(ErrorCodeValidation, msg, &CasdoorDetail{Reason: ReasonOther}, status)
	}
}

func maskedObjectError(op, kind string) *Error {
	return casdoorError(ErrorCodePermissionDenied,
		op+": Casdoor returned the "+kind+" with masked fields; sign in as a global admin (AdminPassword) or use the client credentials of an application",
		&CasdoorDetail{Reason: ReasonMaskedObject}, 0)
}

func validationError(op, msg string) *Error { return NewError(ErrorCodeValidation, op+": "+msg, nil) }

func configError(op, msg string) *Error { return NewError(ErrorCodeConfig, op+": "+msg, nil) }

// required returns a VALIDATION error for the first empty value (Casdoor would
// answer "Phone number is invalid"). Pairs are name, value.
func required(op string, pairs ...string) error {
	for i := 0; i+1 < len(pairs); i += 2 {
		if strings.TrimSpace(pairs[i+1]) == "" {
			return validationError(op, pairs[i]+" must not be empty")
		}
	}
	return nil
}
