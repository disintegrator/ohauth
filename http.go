package ohauth

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type formEncoded interface {
	Values() url.Values
}

type authorizationRequest struct {
	ts       time.Time
	client   *Client
	session  *TokenClaims
	redirect *StrictURL
	scope    *Scope
	state    string
}

func abort(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	w.Write([]byte(msg))
}

func handleCodeAuthorize(p *Provider, r *authorizationRequest) (formEncoded, error) {
	c := r.client
	if c.GrantType != AuthorizationCode {
		return NewError(InvalidRequest, "Client cannot use specified grant type"), nil
	}
	if c.RedirectURI.String() != r.redirect.String() {
		return NewError(InvalidRequest, "Redirect URI is invalid"), nil
	}
	if !c.Scope.Contains(r.scope) {
		return NewError(InvalidScope, "Client cannot offer requested scope"), nil
	}

	codeKey := fmt.Sprintf("%s:%s", r.client.ID, r.session.Subject)
	tc, err := p.Store.FetchToken(codeKey)
	if err != nil || tc == nil || tc.Expires < r.ts.Unix() || tc.Scope.Equals(r.scope) {
		return nil, err
	}

	code, err := p.Tokenizer.Tokenize(tc, r.client.SigningKey)
	if err != nil {
		return nil, err
	}
	return &CodeResponse{code}, nil
}

func handleImplicitAuthorize(p *Provider, r *authorizationRequest) (formEncoded, error) {
	return nil, nil
}

func handleAuthorize(p *Provider, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cid := q.Get("client_id")
	state := q.Get("state")
	rt := q.Get("response_type")
	scope := ParseScope(q.Get("scope"))

	redirect, err := ParseURL(q.Get("redirect_uri"))
	if err != nil {
		panic(err) // TODO redirect and then spew
	}

	if rt != "code" && rt != "token" {
		v := unsupportResponseType.Values()
		v.Set("state", state)
		http.Redirect(w, r, redirect.StringWithParams(v), http.StatusFound)
		return
	}

	client, err := p.Store.FetchClient(cid)
	if err != nil {
		v := unexpectedError.Values()
		v.Set("state", state)
		http.Redirect(w, r, redirect.StringWithParams(v), http.StatusFound)
		panic(err) // TODO redirect and then spew
	}

	if client == nil || client.Status != ClientActive {
		v := clientNotFound.Values()
		v.Set("state", state)
		http.Redirect(w, r, redirect.StringWithParams(v), http.StatusFound)
		panic(err) // TODO return invalid_client
	}

	sc, err := AuthenticateRequest(p.Authenticator, r)
	if err != nil {
		panic(err) // TODO redirect and then spew
	}

	req := &authorizationRequest{
		p.Clock.Now(),
		client,
		sc,
		redirect,
		scope,
		state,
	}

	var resp formEncoded

	switch rt {
	case "code":
		resp, err = handleCodeAuthorize(p, req)
	case "token":
		resp, err = handleImplicitAuthorize(p, req)
	}

	if err != nil {
		v := unexpectedError.Values()
		v.Set("state", state)
		http.Redirect(w, r, redirect.StringWithParams(v), http.StatusFound)
		panic(err)
	}

	v := resp.Values()
	v.Set("state", state)
	http.Redirect(w, r, redirect.StringWithParams(v), http.StatusFound)
}

func handleToken(p *Provider, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cid := q.Get("client_id")
	//csecret := q.Get("client_secret")
	//code := q.Get("code")
	//redirect := q.Get("redirect_uri")
	//username := q.Get("username")
	//password := q.Get("password")

	client, err := p.Store.FetchClient(cid)
	if err != nil {
		panic(err) // TODO redirect and then spew
	}

	if client.GrantType == AuthorizationCode {

	}

}
