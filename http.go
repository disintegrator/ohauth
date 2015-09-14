package ohauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func mergeValues(vs ...url.Values) url.Values {
	out := url.Values{}
	for _, v := range vs {
		for key, val := range v {
			out[key] = val
		}
	}
	return out
}

type context struct {
	provider  *Provider
	writer    http.ResponseWriter
	request   *http.Request
	timestamp time.Time
}

func (c *context) redirect(u string) {
	http.Redirect(c.writer, c.request, u, http.StatusFound)
}

func (c *context) fail(ru *StrictURL, e *Error, state string) {
	v := mergeValues(url.Values{}, e.Values())
	v.Set("state", state)
	c.redirect(ru.StringWithParams(v))
}

func (c *context) json(s int, o interface{}) (err error) {
	c.writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	b, err := json.Marshal(o)
	if err != nil {
		return
	}
	c.writer.WriteHeader(s)
	_, err = c.writer.Write(b)
	return
}

func (c *context) abort(status int, msg string) {
	c.writer.WriteHeader(status)
	c.writer.Write([]byte(msg))
}

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
	scope    *Scope
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

	tc := NewTokenClaims(ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForCode()))
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

	tc := NewTokenClaims(ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForToken(c.GrantType)))
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

type grantRequest struct{}

var grantHandlers = map[string]func(*context, *grantRequest) error{
	"authorization_code": grantWithCode,
	"password":           grantWithPassword,
	"client_credentials": grantWithClient,
}

func grantWithCode(*context, *grantRequest) error     { return errors.New("not implemented") }
func grantWithPassword(*context, *grantRequest) error { return errors.New("not implemented") }
func grantWithClient(*context, *grantRequest) error   { return errors.New("not implemented") }

func handleToken(ctx *context) error {
	if ctx.request.Method != "POST" {
		ctx.abort(http.StatusMethodNotAllowed, "Method not allowed")
		return nil
	}
	if err := ctx.request.ParseForm(); err != nil {
		return err
	}

	f := ctx.request.PostForm
	gt := f.Get("grant_type")
	_, found := grantHandlers[gt]
	if !found {
		ctx.json(http.StatusBadRequest, ErrInvalidGrant)
		return nil
	}

	return nil
}
