package ohauth

// Store defines an interface that is used to store/retrieve/manipulate objects
// used throughout the OAuth framework (typically a database).
type Store interface {
	// CreateClient stores a client
	CreateClient(*Client) error
	// FetchClient retrieves a client by its id
	FetchClient(cid string) (*Client, error)
	// DeleteClient deletes a client by its id
	DeleteClient(cid string) error

	// BlacklistToken invalidate codes and tokens using a token ID
	BlacklistToken(id string) error
	// TokenBlacklisted is used to check if a code or token is invalidated
	TokenBlacklisted(id string) (bool, error)

	// StoreAuthorization records a resource owner's authorisation of a client
	StoreAuthorization(a *Authorization) error
	// FetchAuthorization retrieves an Authorization record
	FetchAuthorization(cid string, sub string) (*Authorization, error)
}
