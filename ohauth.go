package ohauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var defaultClock = &DefaultClock{}
var defaultIssuer = &DefaultIssuer{}
var defaultTokenizer = NewJWTTokenizer(jwt.SigningMethodES256)

type Provider struct {
	// Authorization and Authentication endpoints
	URL *StrictURL
	// Authenticator is used for to parse sessions and authenticate via password grants
	Authenticator Authenticator
	// Data store for clients and tokens
	Store Store
	// Clock that generates timestamps for checking and issuing tokens
	Clock Clock
	// Tokenizer is required to generate code, id, access and refresh tokens
	Tokenizer Tokenizer
	// Issuer is used to determine claim values when issuing tokens
	Issuer Issuer
}

func NewProvider(u *StrictURL, authn Authenticator, store Store) *Provider {
	return &Provider{
		u,
		authn,
		store,
		defaultClock,
		defaultTokenizer,
		defaultIssuer,
	}
}

type CodeRequest struct {
	Timestamp time.Time
	Session   *TokenClaims
	Client    *Client
	Scope     *Scope
	Redirect  *StrictURL
	State     string
}

func (p *Provider) ValidateCodeRequest(cr *CodeRequest) error {
	c := cr.Client

	if c == nil {
		return NewError(InvalidClient, "Client ID is invalid")
	}
	if c.Status != ClientActive {
		return NewError(InvalidClient, "Client is not active")
	}
	if c.GrantType != AuthorizationCode {
		return NewError(InvalidRequest, "Client cannot use specified grant type")
	}
	if c.RedirectURI.String() != cr.Redirect.String() {
		return NewError(InvalidRequest, "Redirect URI is invalid")
	}
	if c.RedirectURI.String() != cr.Redirect.String() {
		return NewError(InvalidRequest, "Redirect URI is invalid")
	}
	if !c.Scope.Contains(cr.Scope) {
		return NewError(InvalidScope, "Client cannot offer requested scope")
	}

	return nil
}

func (p *Provider) CheckAuthorization(cr *CodeRequest) (*CodeResponse, error) {
	if err := p.ValidateCodeRequest(cr); err != nil {
		return nil, err
	}

	codeKey := fmt.Sprintf("%s:%s", cr.Client.ID, cr.Session.Subject)
	tc, err := p.Store.FetchToken(codeKey)
	if err != nil || tc == nil || tc.Expires < cr.Timestamp.Unix() || tc.Scope.Equals(cr.Scope) {
		return nil, err
	}

	code, err := p.Tokenizer.Tokenize(tc, cr.Client.SigningKey)
	if err != nil {
		return nil, err
	}
	return &CodeResponse{code}, nil
	//return &CodeResponse{code, cr.State}, nil
}

func (p *Provider) AuthorizeWithCode(cr *CodeRequest) (*CodeResponse, error) {
	res, err := p.CheckAuthorization(cr)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}

	now := p.Clock.Now()
	tc := NewTokenClaims(now, now.Add(p.Issuer.ExpiryForCode()))
	tc.Issuer = p.URL.String()
	tc.Audience = cr.Client.ID
	tc.Subject = cr.Session.Subject
	tc.Scope = cr.Scope

	if err := p.Store.RecordToken(tc); err != nil {
		return nil, err
	}

	code, err := p.Tokenizer.Tokenize(tc, cr.Client.SigningKey)
	if err != nil {
		return nil, err
	}

	return &CodeResponse{code}, nil
	//return &CodeResponse{code, cr.State}, nil
}

func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		handleAuthorize(p, w, r)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		handleToken(p, w, r)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "POST" {
			mux.ServeHTTP(w, r)
		} else {
			abort(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})
}
