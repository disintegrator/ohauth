package ohauth

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
)

type Tokenizer interface {
	Tokenize(c *Client, tc *TokenClaims) (string, error)
	Parse(c *Client, token string) (*TokenClaims, error)
}

type DefaultTokenizer struct{}

func (*DefaultTokenizer) Tokenize(c *Client, tc *TokenClaims) (string, error) {
	method := jwt.SigningMethodRS256

	header, err := json.Marshal(struct {
		Type      string `json:"typ"`
		Algorithm string `json:"alg"`
	}{"jwt", method.Alg()})
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(tc)
	if err != nil {
		return "", err
	}

	h64 := jwt.EncodeSegment(header)
	b64 := jwt.EncodeSegment(body)
	inp := fmt.Sprintf("%s.%s", h64, b64)
	return method.Sign(inp, c.SigningKey)
}

func (*DefaultTokenizer) Parse(c *Client, raw string) (*TokenClaims, error) {
	token, err := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
		if m, ok := token.Method.(*jwt.SigningMethodRSA); !ok || m.Hash != crypto.SHA256 {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return c.SigningKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, nil
	}

	tc := &TokenClaims{}

	err = mapstructure.Decode(token.Claims, tc)
	if err != nil {
		return nil, err
	}

	return tc, nil
}
