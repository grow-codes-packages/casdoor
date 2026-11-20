package casdoor

import "time"

// TokenSet holds the OAuth tokens of sign-in, refresh and code exchange.
// Its String method never prints tokens.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
	ExpiresAt    time.Time
	Scope        string
}

// String implements fmt.Stringer without the tokens.
func (t TokenSet) String() string {
	return "TokenSet{TokenType:" + t.TokenType + " ExpiresAt:" + t.ExpiresAt.Format(time.RFC3339) + "}"
}

// SignUpInput is the input of SignUp. Username is derived from the e-mail when empty.
type SignUpInput struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
	// EmailCode from SendEmailVerification when the application requires it.
	EmailCode string
}

// SignUpResult is the result of SignUp.
type SignUpResult struct {
	UserID       string // "<organization>/<name>"
	Organization string
	Name         string
}

// SignInInput is the input of SignIn.
type SignInInput struct {
	Username     string // user name or e-mail
	Password     string
	TOTPCode     string
	RecoveryCode string
	RedirectURI  string // default: Config.RedirectURI
}

// EmailPurpose selects the kind of code SendEmailVerification sends.
type EmailPurpose string

// E-mail code purposes.
const (
	// PurposeAuto sends a code to an existing user, else a sign-up code.
	PurposeAuto EmailPurpose = ""
	// PurposeSignUp sends a code for a new address (pass it to SignUp).
	PurposeSignUp EmailPurpose = "signup"
	// PurposeVerify sends a code to an existing user (then VerifyEmail).
	PurposeVerify EmailPurpose = "verify"
)

// VerifyEmailInput is the input of VerifyEmail.
type VerifyEmailInput struct {
	Email string
	Code  string
}

// ResetPasswordInput is the input of ResetPassword.
type ResetPasswordInput struct {
	Email       string
	Code        string
	NewPassword string
}

// AuthorizeURLInput is the input of BuildAuthorizeURL.
type AuthorizeURLInput struct {
	RedirectURI   string
	State         string
	CodeChallenge string
	Scope         string
	Nonce         string
	Extra         map[string]string
}

// ExchangeCodeInput is the input of ExchangeCode.
type ExchangeCodeInput struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
}

// TOTPSetup is the result of SetupTOTP (show the secret once, never log it).
type TOTPSetup struct {
	Secret        string
	URL           string
	RecoveryCodes []string
}

// String implements fmt.Stringer without the secret.
func (s TOTPSetup) String() string { return "TOTPSetup{Secret:" + Redacted + "}" }

// VerifyTOTPInput is the input of VerifyTOTP.
type VerifyTOTPInput struct {
	AccessToken  string
	Secret       string
	Code         string
	RecoveryCode string
}

// SMTPSettings configures EnsureEmailProvider.
type SMTPSettings struct {
	Name       string // default "provider-email"
	Host       string
	Port       int
	From       string
	FromName   string // default "Casdoor"
	Username   string // default From
	Password   Secret
	DisableSSL bool
	Title      string // default "Verification code"
	Content    string // default "Your verification code is %s"
}

// EnsureOrganizationInput configures EnsureOrganization.
type EnsureOrganizationInput struct {
	Name            string
	DisplayName     string
	PasswordOptions []string // default ["AtLeast8"]
	DisableTOTP     bool
}

// EnsureApplicationInput configures EnsureApplication. Zero values use the
// config (name, organization, client credentials) or the documented defaults.
type EnsureApplicationInput struct {
	Name                   string
	Organization           string
	DisplayName            string
	ClientID               string
	ClientSecret           Secret
	RedirectURIs           []string
	GrantTypes             []string // default authorization_code, refresh_token
	DisableSignUp          bool
	SignUpEmailCode        bool
	Providers              []string
	ExpireInHours          int // default 1
	RefreshExpireInHours   int // default 168
	FailedSigninLimit      int // default 5
	FailedSigninFrozenTime int // default 15 (minutes)
	Cert                   string
}

// ApplicationInfo is the result of EnsureApplication.
type ApplicationInfo struct {
	Name         string
	Organization string
	ClientID     string
	ClientSecret Secret
	RedirectURIs []string
	Created      bool
}

// EnsureUserInput configures EnsureUser.
type EnsureUserInput struct {
	Email        string
	Username     string
	Password     Secret
	DisplayName  string
	Unverified   bool // default: e-mail verified
	Roles        []string
	Organization string
}

// User is a Casdoor user (subset).
type User struct {
	UserID        string
	Organization  string
	Name          string
	ID            string
	Email         string
	DisplayName   string
	EmailVerified bool
	IsForbidden   bool
	Created       bool
}

// RoleInfo is one entry of EnsureRoles.
type RoleInfo struct {
	Name    string
	Created bool
}
