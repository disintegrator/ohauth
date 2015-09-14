package ohauth

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var issuer = &defaultIssuer{}
var tokenizer = NewJWTTokenizer(jwt.SigningMethodRS256)

// Provider configures an OAuth 2.0 provider that can authorize clients by
// issuing signed access tokens
type Provider struct {
	// Authorization and Authentication endpoints
	URL *StrictURL
	// Authenticator is used for to parse sessions and authenticate via password grants
	Authenticator Authenticator
	// Data store for clients and tokens
	Store Store
	// Tokenizer is required to generate code, id, access and refresh tokens
	Tokenizer Tokenizer
	// Issuer is used to determine claim values when issuing tokens
	Issuer Issuer
}

// NewProvider creates a provider configured with the default tokenizer and
// issuer.
func NewProvider(u *StrictURL, authn Authenticator, store Store) *Provider {
	return &Provider{
		u,
		authn,
		store,
		tokenizer,
		issuer,
	}
}

func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(p.URL.Path+"/authorize", func(w http.ResponseWriter, r *http.Request) {
		handleAuthorize(&context{p, w, r, time.Now()})
	})
	mux.HandleFunc(p.URL.Path+"/token", func(w http.ResponseWriter, r *http.Request) {
		handleToken(&context{p, w, r, time.Now()})
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "POST" {
			mux.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
		}
	})
}
