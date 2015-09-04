package ohauth

import (
	"net/url"
	"time"
)

const (
	BearerToken = "Bearer"
)

type TokenClaims struct {
	ID       string `json:"jti"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	Issued   int64  `json:"iat"`
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Scope    *Scope `json:"scope,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

func NewTokenClaims(iat time.Time, exp time.Time) *TokenClaims {
	return &TokenClaims{
		ID:      randID(),
		Expires: exp.Unix(),
		Issued:  iat.Unix(),
	}
}

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	Expires      time.Time `json:"expires_in"`
	Scope        *Scope    `json:"scope"`
}

type CodeResponse struct {
	Code string `json:"code"`
}

func (r *CodeResponse) Values() url.Values {
	v := url.Values{}
	v.Set("code", r.Code)
	return v
}
