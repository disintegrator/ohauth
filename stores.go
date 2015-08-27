package ohauth

type Store interface {
	CreateClient(*Client) error
	FetchClient(cid string) (*Client, error)
	DeleteClient(cid string) error

	RecordToken(tc *TokenClaims) error
	FetchToken(jti string) (*TokenClaims, error)
	BlacklistToken(jti string) error
	TokenBlacklisted(jti string) (bool, error)
}
