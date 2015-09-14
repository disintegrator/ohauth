package ohauth

import "net/http"

// Authenticator is responsible for determining how to authenticate users
type Authenticator interface {
	Verify(sig string, client *Client) (*TokenClaims, error)
	Authenticate(username, password string, client *Client) (*TokenClaims, error)
}

func authenticateRequest(r *http.Request, a Authenticator, client *Client) (*TokenClaims, error) {
	c, err := r.Cookie("sid")
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	//if !c.HttpOnly || !c.Secure {
	//	return nil, fmt.Errorf("unsafe session cookie cannot be used for authentication")
	//}
	return a.Verify(c.Value, client)
}
