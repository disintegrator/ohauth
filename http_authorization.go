package ohauth

import (
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (c *context) redirectAuthorization() {
	next := c.provider.URL.Clone()
	next.Path += "/dialog"
	next.RawQuery = c.request.URL.RawQuery
	c.redirect(next.String())
}

type authorizationRequest struct {
	client   *Client
	session  *TokenClaims
	redirect *StrictURL
	scope    Scope
	state    string
	prompted bool
}

var authorizeHandlers = map[string]func(*context, *authorizationRequest) error{
	"code":  authorizeWithCode,
	"token": authorizeWithToken,
}

func authorizeWithCode(ctx *context, r *authorizationRequest) error {
	p := ctx.provider
	c := r.client
	cid := r.client.ID
	uid := r.session.Subject
	v := url.Values{}
	v.Set("state", r.state)

	if c.GrantType != AuthorizationCode {
		ctx.fail(r.redirect, ErrWrongGrant, r.state)
		return nil
	}

	tc := NewTokenClaims(RoleCode, ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForCode()))
	tc.ID = randID()
	tc.Audience = cid
	tc.Subject = r.session.Subject
	tc.Issuer = p.URL.String()
	tc.Scope = r.scope
	tc.Grant = "authorization_code"

	a, err := p.Store.FetchAuthorization(cid, uid)
	if err != nil {
		return err
	}

	authorized := a != nil && a.Scope.Equals(r.scope)

	if !authorized && !r.prompted {
		ctx.redirectAuthorization()
		return nil
	}

	if r.prompted {
		err := p.Store.StoreAuthorization(NewAuthorization(cid, uid, r.scope))
		if err != nil {
			return err
		}
	}

	code, err := p.Tokenizer.Tokenize(tc, r.client.Keys.Sign)
	if err != nil {
		return err
	}
	v.Set("code", code)

	ctx.redirect(r.redirect.StringWithParams(v))
	return nil
}

func authorizeWithToken(ctx *context, r *authorizationRequest) error {
	p := ctx.provider
	c := r.client
	v := url.Values{}
	v.Set("state", r.state)

	if c.GrantType != Implicit {
		ctx.fail(r.redirect, ErrWrongGrant, r.state)
		return nil
	}

	cid := r.client.ID
	uid := r.session.Subject
	a, err := p.Store.FetchAuthorization(cid, uid)
	if err != nil {
		return err
	}
	authorized := a != nil && a.Scope.Equals(r.scope)
	if !authorized && !r.prompted {
		ctx.redirectAuthorization()
		return nil
	}
	if r.prompted {
		err := p.Store.StoreAuthorization(NewAuthorization(cid, uid, r.scope))
		if err != nil {
			return err
		}
	}

	tc := NewTokenClaims(RoleAccessToken, ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForToken(c.GrantType)))
	tc.ID = randID()
	tc.Audience = cid
	tc.Subject = r.session.Subject
	tc.Issuer = p.URL.String()
	tc.Scope = r.scope
	tc.Grant = "implicit"

	at, err := p.Tokenizer.Tokenize(tc, r.client.Keys.Sign)
	if err != nil {
		return err
	}

	v.Set("access_token", at)
	v.Set("expires_in", strconv.FormatInt(tc.Expires-time.Now().Unix(), 10))
	ctx.redirect(r.redirect.StringWithFragment(v))
	return nil
}

func handleAuthorize(ctx *context) error {
	p := ctx.provider
	err := ctx.request.ParseForm()
	if err != nil {
		ctx.abort(http.StatusBadRequest, "Bad request")
		return nil
	}
	q := ctx.request.Form
	if ctx.request.Method == "POST" {
		q = ctx.request.PostForm
	}
	state := q.Get("state")
	scope := ParseScope(q.Get("scope"))
	prompted := ctx.request.Method == "POST"
	v := url.Values{}
	v.Set("state", state)

	ru, err := ParseURL(q.Get("redirect_uri"))
	if err != nil {
		ctx.abort(http.StatusBadRequest, "Bad redirect uri")
		return nil
	}

	handler, found := authorizeHandlers[q.Get("response_type")]
	if !found {
		ctx.redirect(ru.StringWithParams(mergeValues(ErrUnsupportResponseType.Values(), v)))
		return nil
	}

	client, err := p.Store.FetchClient(q.Get("client_id"))
	if err != nil {
		return err
	}
	if client == nil || client.Status != ClientActive {
		ctx.redirect(ru.StringWithParams(mergeValues(ErrClientNotFound.Values(), v)))
		return nil
	}
	if client.RedirectURI.String() != ru.String() {
		ctx.redirect(ru.StringWithParams(mergeValues(ErrBadRedirect.Values(), v)))
		return nil
	}
	if !client.Scope.Contains(scope) {
		ctx.fail(ru, ErrScopeNotAllowed, state)
		return nil
	}

	sc, err := authenticateRequest(ctx.request, p.Authenticator, client)
	if err != nil {
		panic(err) // TODO redirect and then spew
	}

	req := &authorizationRequest{client, sc, ru, scope, state, prompted}

	return handler(ctx, req)
}
