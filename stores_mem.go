package ohauth

import (
	"fmt"
	"sync"
)

// TestingStore is a Store implementation that may be used for testing and
// experimenting with OhAuth. It is a simple memory-based store.
type TestingStore struct {
	*sync.Mutex
	authz     map[string]*Authorization
	clients   map[string]*Client
	tokens    map[string]*TokenClaims
	blacklist map[string]bool
}

// NewTestingStore creates an instace of a TestingStore
func NewTestingStore() (*TestingStore, error) {
	return &TestingStore{
		&sync.Mutex{},
		make(map[string]*Authorization, 0),
		make(map[string]*Client, 0),
		make(map[string]*TokenClaims, 0),
		make(map[string]bool, 0),
	}, nil
}

// CreateClient stores a client
func (s *TestingStore) CreateClient(c *Client) error {
	s.Lock()
	defer s.Unlock()
	s.clients[c.ID] = c
	return nil
}

// FetchClient retrieves a client by its id
func (s *TestingStore) FetchClient(cid string) (*Client, error) {
	return s.clients[cid], nil
}

// DeleteClient deletes a client by its id
func (s *TestingStore) DeleteClient(cid string) error {
	s.Lock()
	defer s.Unlock()
	delete(s.clients, cid)
	return nil
}

// BlacklistToken invalidate codes and tokens using a token ID
func (s *TestingStore) BlacklistToken(id string) error {
	s.Lock()
	defer s.Unlock()
	s.blacklist[id] = true
	return nil
}

// TokenBlacklisted is used to check if a code or token is invalidated
func (s *TestingStore) TokenBlacklisted(id string) (bool, error) {
	return s.blacklist[id], nil
}

// StoreAuthorization records a resource owner's authorisation of a client
func (s *TestingStore) StoreAuthorization(a *Authorization) error {
	s.Lock()
	defer s.Unlock()
	s.authz[fmt.Sprintf("%s:%s", a.CID, a.UID)] = a
	return nil
}

// FetchAuthorization retrieves an Authorization record
func (s *TestingStore) FetchAuthorization(cid, uid string) (*Authorization, error) {
	return s.authz[fmt.Sprintf("%s:%s", cid, uid)], nil
}
