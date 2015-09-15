package ohauth

import "time"

const (
	BearerToken = "Bearer"
)

const (
	RoleIdentity     = "identity"
	RoleCode         = "code"
	RoleAccessToken  = "access_token"
	RoleRefreshToken = "refresh_token"
)

type TokenClaims struct {
	ID       string `json:"jti"`
	Role     string `json:"role"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	Issued   int64  `json:"iat"`
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Grant    string `json:"grant"`
	Scope    *Scope `json:"scope,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

func (tc *TokenClaims) Map() map[string]interface{} {
	m := map[string]interface{}{
		"jti":   tc.ID,
		"role":  tc.Role,
		"aud":   tc.Audience,
		"exp":   tc.Expires,
		"iat":   tc.Issued,
		"iss":   tc.Issuer,
		"sub":   tc.Subject,
		"grant": tc.Grant,
	}

	if tc.Scope != nil {
		m["scope"] = tc.Scope
	}
	if tc.Nonce != "" {
		m["nonce"] = tc.Nonce
	}
	return m
}

func NewTokenClaims(role string, iat time.Time, exp time.Time) *TokenClaims {
	return &TokenClaims{
		ID:      randID(),
		Role:    role,
		Expires: exp.Unix(),
		Issued:  iat.Unix(),
	}
}
