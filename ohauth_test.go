package ohauth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

const authnKey = "MHcCAQEEIHG6obX5AhdkAjKdA2XhkoyHGyB3sdKlPK7BjGLTgPznoAoGCCqGSM49AwEHoUQDQgAEQQKD8BGFT1WBv2p9q2MbLFuTkRZnQYp8sBOp290kBv914R_M-pOEV2fdH8hCYhUYU31tv8qPog1z_a3771UaYA"

type TestAuthenticator struct {
	URL       *StrictURL
	Key       []byte
	Tokenizer Tokenizer
}

func NewTestAuthenticator(u *StrictURL) (Authenticator, error) {
	return &TestAuthenticator{u, []byte("monkeys"), NewJWTTokenizer(jwt.SigningMethodHS256)}, nil
}

func (a *TestAuthenticator) Verify(sig string, client *Client) (*TokenClaims, error) {
	return a.Tokenizer.Parse(sig, a.Key)
}

func (a *TestAuthenticator) Authenticate(username, password string, client *Client) (*TokenClaims, error) {
	iat := time.Now()
	exp := iat.Add(1 * time.Hour)
	tc := NewTokenClaims(RoleIdentity, iat, exp)

	tc.Issuer = a.URL.String()
	tc.Subject = username
	tc.Audience = client.ID
	return tc, nil
}

var testProvider *Provider

func init() {
	authz, err := ParseURL("https://authz.example.com")
	if err != nil {
		panic(err)
	}
	authn, err := ParseURL("https://authn.example.com")
	if err != nil {
		panic(err)
	}
	a, err := NewTestAuthenticator(authn)
	if err != nil {
		panic(err)
	}
	s, err := NewTestingStore()
	if err != nil {
		panic(err)
	}

	testProvider = NewProvider(authz, a, s)
}
