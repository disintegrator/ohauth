package ohauth

import "net/http"

// Authenticator is responsible for determining how to authenticate users
type Authenticator interface {
	Verify(sig string, client *Client) (*TokenClaims, error)
	AuthenticateCredentials(username, password string, client *Client) (*TokenClaims, error)
	AuthenticateRequest(r *http.Request, client *Client) (*TokenClaims, error)
}
