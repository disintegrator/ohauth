package ohauth

import "time"

const (
	BearerToken = "Bearer"
)

type TokenClaims struct {
	ID       string `json:"jti" mapstructure:"jti"`
	Audience string `json:"aud" mapstructure:"aud"`
	Expires  int64  `json:"exp" mapstructure:"exp"`
	Issued   int64  `json:"iat" mapstructure:"iat"`
	Issuer   string `json:"iss" mapstructure:"iss"`
	Subject  string `json:"sub" mapstructure:"sub"`
	Grant    string `json:"grant" mapstructure:"grant"`
	Scope    *Scope `json:"scope,omitempty" mapstructure:"scope,omitempty"`
	Nonce    string `json:"nonce,omitempty" mapstructure:"nonce,omitempty"`
}

func NewTokenClaims(iat time.Time, exp time.Time) *TokenClaims {
	return &TokenClaims{
		ID:      randID(),
		Expires: exp.Unix(),
		Issued:  iat.Unix(),
	}
}
