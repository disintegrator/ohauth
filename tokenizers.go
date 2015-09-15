package ohauth

import (
	"fmt"
	"reflect"

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

	tc := &TokenClaims{}

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  tc,
		TagName: "json",
		DecodeHook: func(from, to reflect.Type, data interface{}) (interface{}, error) {
			if from.Kind() == reflect.String && to.Kind() == reflect.TypeOf(tc.Scope).Kind() {
				return ParseScope(data.(string)), nil
			}
			return data, nil
		},
	})
	if err != nil {
		return nil, err
	}
	err = d.Decode(token.Claims)
	if err != nil {
		return nil, err
	}

	return tc, nil
}
