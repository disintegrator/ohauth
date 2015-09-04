package ohauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Authenticator is responsible for determining how to authenticate users
type Authenticator interface {
	Verify(sig string) (*TokenClaims, error)
	Authenticate(username, password string) (*TokenClaims, error)
}

type defaultAuthenticator struct {
	endpoint   *StrictURL
	tokenizer  Tokenizer
	signingKey []byte
}

// NewAuthenticator creates an instance of an authenticator that can read
// user sessions represented as JWTs
func NewAuthenticator(endpoint *StrictURL, ssk []byte) Authenticator {
	defaultTokenizer := NewJWTTokenizer(jwt.SigningMethodRS256)
	return &defaultAuthenticator{endpoint, defaultTokenizer, ssk}
}

func (a *defaultAuthenticator) Verify(sig string) (*TokenClaims, error) {
	tc, err := a.tokenizer.Parse(sig, a.signingKey)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if tc.Expires < now || tc.Issuer != a.endpoint.String() {
		return nil, nil
	}
	return tc, nil
}

func (a *defaultAuthenticator) Authenticate(username, password string) (*TokenClaims, error) {
	j, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	cl := &http.Client{
		Jar:     j,
		Timeout: 10 * time.Second,
	}

	csrf, err := getCSRFToken(cl, a.endpoint)

	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", a.endpoint.String(), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Csrf-Token", csrf)
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var sc *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "sid" {
			sc = c
			break
		}
	}
	if sc == nil {
		return nil, nil
	}
	if !sc.Secure || !sc.HttpOnly {
		return nil, fmt.Errorf("unsafe session cookie cannot be used for authentication")
	}

	return a.Verify(sc.Value)
}

func getCSRFToken(cl *http.Client, u *StrictURL) (string, error) {
	endpoint := u.Clone()
	endpoint.Path = "/csrf"
	req, err := http.NewRequest("GET", endpoint.String(), nil)
	if err != nil {
		return "", err
	}
	res, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	token := res.Header.Get("X-CSRF-Token")
	return token, nil
}

// AuthenticateRequest uses an authenticator to determine if a requested is from
// an authenticated user
func AuthenticateRequest(a Authenticator, r *http.Request) (*TokenClaims, error) {
	c, err := r.Cookie("sid")
	if err != nil {
		return nil, err
	}
	if !c.HttpOnly || !c.Secure {
		return nil, fmt.Errorf("unsafe session cookie cannot be used for authentication")
	}
	return a.Verify(c.Value)
}
