package ohauth

import (
	"encoding/json"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
)

type Tokenizer interface {
	Tokenize(tc *TokenClaims, signingKey []byte) (string, error)
	Parse(token string, signingKey []byte) (*TokenClaims, error)
}

type jwtTokenizer struct {
	method jwt.SigningMethod
}

func NewJWTTokenizer(signingMethod jwt.SigningMethod) Tokenizer {
	return &jwtTokenizer{signingMethod}
}

func (t *jwtTokenizer) Tokenize(tc *TokenClaims, signingKey []byte) (string, error) {
	if tc.Expires == 0 {
		return "", fmt.Errorf("Token expiry not set")
	}

	header, err := json.Marshal(struct {
		Type      string `json:"typ"`
		Algorithm string `json:"alg"`
	}{"jwt", t.method.Alg()})
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
	return t.method.Sign(inp, signingKey)
}

func (t *jwtTokenizer) Parse(raw string, signingKey []byte) (*TokenClaims, error) {
	if t.method == nil {
		return nil, fmt.Errorf("No signing method specified")
	}
	token, err := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != t.method.Alg() {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
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
