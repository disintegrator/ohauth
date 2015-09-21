package ohauth

import "time"

type Issuer interface {
	ExpiryForToken(grantType string) time.Duration
	ExpiryForCode() time.Duration
	ScopePermitted(scope Scope, grantType string) bool
}

type defaultIssuer struct{}

func (d *defaultIssuer) ExpiryForCode() time.Duration {
	return 60 * time.Minute
}

func (d *defaultIssuer) ExpiryForToken(grantType string) time.Duration {
	switch grantType {
	case Implicit:
		return 2 * time.Hour
	case RefreshToken:
		return 60 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func (*defaultIssuer) ScopePermitted(Scope, string) bool {
	return true
}
