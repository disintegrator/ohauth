package ohauth

import "time"

// Issuer defines parameters for tokens and scopes
type Issuer interface {
	// ExpiryForToken returns the expiry duration for token issued under a
	// specified grant type
	ExpiryForToken(grantType string) time.Duration
	// ExpiryForCode returns the expiry duration for codes issued with the
	// Authorization Code grant type
	ExpiryForCode() time.Duration
	// ScopePermitted determines if a scope can be issued under a certain grant
	// type
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
