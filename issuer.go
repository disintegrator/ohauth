package ohauth

import "time"

type Issuer interface {
	ExpiryForToken(grantType string) time.Duration
	ExpiryForCode() time.Duration
}

type DefaultIssuer struct{}

func (d *DefaultIssuer) ExpiryForCode() time.Duration {
	return 5 * time.Minute
}

func (d *DefaultIssuer) ExpiryForToken(grantType string) time.Duration {
	switch grantType {
	case Implicit:
		return 2 * time.Hour
	case Refresh:
		return 60 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}
