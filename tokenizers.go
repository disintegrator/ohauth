package ohauth

import (
	"fmt"
	"reflect"

	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
)

// Tokenizer defines an interface that can create OAuth token strings
// (codes, access and refresh tokens) from TokenClaims and parse strings back
// into TokenClaims.
type Tokenizer interface {
	// Tokenize converts TokenClaims into a signed string using a signing key
	Tokenize(tc *TokenClaims, signingKey []byte) (string, error)
	// Parse takes a signed token string, verifies its authenticity and returns
	// the TokenClaims it carries
	Parse(token string, verifyKey []byte) (*TokenClaims, error)
}

type jwtTokenizer struct {
	method jwt.SigningMethod
}

// NewJWTTokenizer creates a Tokenizer that creates and parses JWT tokens
func NewJWTTokenizer(signingMethod jwt.SigningMethod) Tokenizer {
	return &jwtTokenizer{signingMethod}
}

func (t *jwtTokenizer) Tokenize(tc *TokenClaims, signingKey []byte) (string, error) {
	if tc.Expires == 0 {
		return "", fmt.Errorf("Token expiry not set")
	}

	token := jwt.New(t.method)
	token.Claims = tokenClaimsToMap(tc)
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

func tokenClaimsToMap(tc *TokenClaims) map[string]interface{} {
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
