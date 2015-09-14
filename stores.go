package ohauth

type Store interface {
	CreateClient(*Client) error
	FetchClient(cid string) (*Client, error)
	DeleteClient(cid string) error

	BlacklistToken(jti string) error
	TokenBlacklisted(jti string) (bool, error)

	StoreAuthorization(a *Authorization) error
	FetchAuthorization(cid string, sub string) (*Authorization, error)
}
