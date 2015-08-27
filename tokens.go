package ohauth

import "time"

type TokenType string

const (
	Bearer TokenType = "Bearer"
)

type TokenClaims struct {
	ID       string `json:"jti"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	Issued   int64  `json:"iat"`
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Scope    *Scope `json:"scope,omitempty"`
}

func NewTokenClaims(iat time.Time, exp time.Time) (*TokenClaims, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}
	return &TokenClaims{
		ID:      id,
		Expires: exp.Unix(),
		Issued:  iat.Unix(),
	}, nil
}

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    TokenType `json:"token_type"`
	Expires      time.Time `json:"expires_in"`
	Scope        *Scope    `json:"scope"`
}

type CodeResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}
