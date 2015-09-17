package ohauth

import (
	"fmt"
	"sync"
)

type TestingStore struct {
	*sync.Mutex
	authz     map[string]*Authorization
	clients   map[string]*Client
	tokens    map[string]*TokenClaims
	blacklist map[string]bool
}

func NewTestingStore() (*TestingStore, error) {
	return &TestingStore{
		&sync.Mutex{},
		make(map[string]*Authorization, 0),
		make(map[string]*Client, 0),
		make(map[string]*TokenClaims, 0),
		make(map[string]bool, 0),
	}, nil
}

func (s *TestingStore) CreateClient(c *Client) error {
	s.Lock()
	defer s.Unlock()
	s.clients[c.ID] = c
	return nil
}

func (s *TestingStore) FetchClient(cid string) (*Client, error) {
	return s.clients[cid], nil
}

func (s *TestingStore) DeleteClient(cid string) error {
	s.Lock()
	defer s.Unlock()
	delete(s.clients, cid)
	return nil
}

func (s *TestingStore) BlacklistToken(jti string) error {
	s.Lock()
	defer s.Unlock()
	s.blacklist[jti] = true
	return nil
}

func (s *TestingStore) TokenBlacklisted(jti string) (bool, error) {
	return s.blacklist[jti], nil
}

func (s *TestingStore) StoreAuthorization(a *Authorization) error {
	s.Lock()
	defer s.Unlock()
	s.authz[fmt.Sprintf("%s:%s", a.CID, a.UID)] = a
	return nil
}

func (s *TestingStore) FetchAuthorization(cid, uid string) (*Authorization, error) {
	return s.authz[fmt.Sprintf("%s:%s", cid, uid)], nil
}
