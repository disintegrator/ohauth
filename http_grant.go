package ohauth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"time"
)

type grantRequest struct {
	client *Client
	form   url.Values
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

var grantHandlers = map[string]func(*context, *grantRequest) error{
	AuthorizationCode: grantWithCode,
	Password:          grantWithPassword,
	ClientCredentials: grantWithClient,
	RefreshToken:      grantWithRefreshToken,
}

func grantWithCode(ctx *context, gr *grantRequest) error {
	c := gr.client
	p := ctx.provider
	ru, err := ParseURL(gr.form.Get("redirect_uri"))
	if err != nil {
		ctx.json(http.StatusBadRequest, ErrBadRedirect)
		return nil
	}

	if c.RedirectURI.String() != ru.String() {
		ctx.json(http.StatusBadRequest, ErrBadRedirect)
		return nil
	}

	tc, err := p.Tokenizer.Parse(gr.form.Get("code"), c.Keys.Verify)
	if err != nil {
		return err
	}

	authz, err := p.Store.FetchAuthorization(c.ID, tc.Subject)
	if err != nil {
		return err
	}
	if authz == nil {
		ctx.json(http.StatusForbidden, ErrUnauthorized)
		return nil
	}

	bl, err := p.Store.TokenBlacklisted(tc.ID)
	if err != nil {
		return err
	}
	if bl {
		ctx.json(http.StatusForbidden, ErrCodeUsed)
		return nil
	}

	scope := c.Scope.Contains(tc.Scope) && p.Issuer.ScopePermitted(tc.Scope, c.GrantType)
	if !scope {
		ctx.json(http.StatusForbidden, ErrScopeNotAllowed)
		return nil
	}

	role := tc.Role == RoleCode
	aud := tc.Audience == c.ID
	iss := tc.Issuer == p.URL.String()
	exp := tc.Expires > ctx.timestamp.Unix()
	grant := tc.Grant == AuthorizationCode
	if !role || !aud || !iss || !exp || !grant || !scope {
		ctx.json(http.StatusForbidden, ErrAccessDenied)
		return nil
	}

	at := NewTokenClaims(RoleAccessToken, ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForToken(c.GrantType)))
	at.ID = randID()
	at.Audience = c.ID
	at.Subject = tc.Subject
	at.Issuer = p.URL.String()
	at.Scope = tc.Scope
	at.Grant = AuthorizationCode

	rt := NewTokenClaims(RoleRefreshToken, ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForToken(RefreshToken)))
	rt.ID = randID()
	rt.Subject = at.ID
	at.Issuer = p.URL.String()

	sat, err := p.Tokenizer.Tokenize(at, c.Keys.Sign)
	if err != nil {
		return err
	}
	srt, err := p.Tokenizer.Tokenize(rt, c.Keys.Sign)
	if err != nil {
		return err
	}

	if err := p.Store.BlacklistToken(tc.ID); err != nil {
		return err
	}

	ctx.json(http.StatusOK, &tokenResponse{
		sat,
		"bearer",
		at.Expires - time.Now().Unix(),
		srt,
	})

	return nil
}
func grantWithPassword(ctx *context, gr *grantRequest) error {
	p := ctx.provider
	c := gr.client
	f := gr.form
	scope := ParseScope(f.Get("scope"))
	username := f.Get("username")
	password := f.Get("password")

	s, err := p.Authenticator.Authenticate(username, password, c)
	if err != nil {
		return err
	}
	if s == nil {
		ctx.json(http.StatusForbidden, ErrAccessDenied)
		return nil
	}

	validscope := c.Scope.Contains(scope) && p.Issuer.ScopePermitted(scope, c.GrantType)
	if !validscope {
		ctx.json(http.StatusForbidden, ErrScopeNotAllowed)
		return nil
	}

	at := NewTokenClaims(RoleAccessToken, ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForToken(c.GrantType)))
	at.ID = randID()
	at.Audience = c.ID
	at.Subject = s.Subject
	at.Issuer = p.URL.String()
	at.Scope = scope
	at.Grant = Password

	rt := NewTokenClaims(RoleRefreshToken, ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForToken(RefreshToken)))
	rt.ID = randID()
	rt.Subject = at.ID
	at.Issuer = p.URL.String()

	sat, err := p.Tokenizer.Tokenize(at, c.Keys.Sign)
	if err != nil {
		return err
	}
	srt, err := p.Tokenizer.Tokenize(rt, c.Keys.Sign)
	if err != nil {
		return err
	}

	ctx.json(http.StatusOK, &tokenResponse{
		sat,
		"bearer",
		at.Expires - time.Now().Unix(),
		srt,
	})

	return nil
}
func grantWithClient(ctx *context, gr *grantRequest) error {
	p := ctx.provider
	c := gr.client
	f := gr.form
	scope := ParseScope(f.Get("scope"))

	validscope := c.Scope.Contains(scope) && p.Issuer.ScopePermitted(scope, c.GrantType)
	if !validscope {
		ctx.json(http.StatusForbidden, ErrScopeNotAllowed)
		return nil
	}

	at := NewTokenClaims(RoleAccessToken, ctx.timestamp, ctx.timestamp.Add(p.Issuer.ExpiryForToken(c.GrantType)))
	at.ID = randID()
	at.Audience = c.ID
	at.Subject = c.ID
	at.Issuer = p.URL.String()
	at.Scope = scope
	at.Grant = ClientCredentials

	sat, err := p.Tokenizer.Tokenize(at, c.Keys.Sign)
	if err != nil {
		return err
	}

	ctx.json(http.StatusOK, &tokenResponse{
		sat,
		"bearer",
		at.Expires - time.Now().Unix(),
		"",
	})

	return nil
}
func grantWithRefreshToken(ctx *context, gr *grantRequest) error {
	return errors.New("not implemented")
}

func handleGrant(ctx *context) error {
	p := ctx.provider
	if ctx.request.Method != "POST" {
		ctx.abort(http.StatusMethodNotAllowed, "Method not allowed")
		return nil
	}
	if err := ctx.request.ParseForm(); err != nil {
		return err
	}

	f := ctx.request.PostForm
	gt := f.Get("grant_type")
	handler, found := grantHandlers[gt]
	if !found {
		ctx.json(http.StatusBadRequest, ErrInvalidGrant)
		return nil
	}

	client, err := p.Store.FetchClient(f.Get("client_id"))
	if err != nil {
		return err
	}
	if client == nil || client.Status != ClientActive {
		ctx.json(http.StatusBadRequest, ErrClientNotFound)
		return nil
	}

	if gt != client.GrantType && gt != RefreshToken {
		ctx.json(http.StatusBadRequest, ErrInvalidGrant)
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(f.Get("client_secret")), []byte(client.Secret)) != 1 {
		ctx.json(http.StatusForbidden, ErrAccessDenied)
		return nil
	}

	return handler(ctx, &grantRequest{client, f})
}
