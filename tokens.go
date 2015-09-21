package ohauth

import "time"

// Role identifies the role of a JWT token
const (
	RoleIdentity     = "identity"
	RoleCode         = "code"
	RoleAccessToken  = "access_token"
	RoleRefreshToken = "refresh_token"
)

// TokenClaims captures information about a token or code that is issued to
// clients
type TokenClaims struct {
	ID       string `json:"jti"`
	Role     string `json:"role"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	Issued   int64  `json:"iat"`
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Grant    string `json:"grant"`
	Scope    Scope  `json:"scope,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

// NewTokenClaims creates an instance of TokenClaims initialised with some basic
// claims include an ID, role, issue date and expiry
func NewTokenClaims(role string, iat time.Time, exp time.Time) *TokenClaims {
	return &TokenClaims{
		ID:      randID(),
		Role:    role,
		Expires: exp.Unix(),
		Issued:  iat.Unix(),
	}
}
