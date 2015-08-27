package ohauth

type CodeRequest struct {
	Provider     *Provider
	Client       *Client
	SessionToken *TokenClaims
	Scope        *Scope
	State        string
}

func (cr *CodeRequest) ValidateClient() (*Error, error) {
	p := cr.Provider
	client := cr.Client

	if client == nil {
		return InvalidClient.DocumentedError(
			p, "client not found", cr.State,
		), nil
	}

	if client.GrantType != AuthorizationCode {
		return InvalidRequest.DocumentedError(
			p, "client cannot use specified grant type", cr.State,
		), nil
	}

	if !client.Scope.Contains(cr.Scope) {
		return InvalidScope.DocumentedError(
			p, "client cannot issue requested scope", cr.State,
		), nil
	}
	return nil, nil
}

func (cr *CodeRequest) ValidateSession() (*Error, error) {
	c := cr.Client
	p := cr.Provider
	st := cr.SessionToken
	now := p.Now().Unix()

	if st.Issued > now {
		return AccessDenied.DocumentedError(p, "Invalid session", cr.State), nil
	}
	if st.Expires < now {
		return AccessDenied.DocumentedError(p, "Token expired", cr.State), nil
	}

	if st.Issuer == "" || st.Issuer != p.Base.String() {
		return AccessDenied.DocumentedError(p, "Token not issued by client", cr.State), nil
	}

	if st.Audience != c.ID {
		return AccessDenied.DocumentedError(p, "Authentication failed", cr.State), nil
	}

	blacklisted, err := p.TokenBlacklisted(st.ID)
	if err != nil {
		return nil, err
	}
	if blacklisted {
		return AccessDenied.DocumentedError(p, "Authentication failed", cr.State), nil
	}

	return nil, nil
}

func (cr *CodeRequest) Validate() (*Error, error) {
	verr, err := cr.ValidateClient()
	if verr != nil || err != nil {
		return verr, err
	}
	verr, err = cr.ValidateSession()
	if verr != nil || err != nil {
		return verr, err
	}
	return nil, nil
}
