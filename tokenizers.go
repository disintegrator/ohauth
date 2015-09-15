package ohauth

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
)

type Tokenizer interface {
	Tokenize(tc *TokenClaims, signingKey []byte) (string, error)
	Parse(token string, verifyKey []byte) (*TokenClaims, error)
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

	token := jwt.New(t.method)
	token.Claims = tc.Map()
	return token.SignedString(signingKey)
}

func (t *jwtTokenizer) Parse(raw string, verifyKey []byte) (*TokenClaims, error) {
	if t.method == nil {
		return nil, fmt.Errorf("No signing method specified")
	}
	token, err := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != t.method.Alg() {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return verifyKey, nil
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
