package ohauth

import (
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const authnKey = "MHcCAQEEIHG6obX5AhdkAjKdA2XhkoyHGyB3sdKlPK7BjGLTgPznoAoGCCqGSM49AwEHoUQDQgAEQQKD8BGFT1WBv2p9q2MbLFuTkRZnQYp8sBOp290kBv914R_M-pOEV2fdH8hCYhUYU31tv8qPog1z_a3771UaYA"

type TestAuthenticator struct {
	URL       *StrictURL
	Key       []byte
	Tokenizer Tokenizer
}

func NewTestAuthenticator(u *StrictURL) (Authenticator, error) {
	return &TestAuthenticator{u, []byte("monkeys"), NewJWTTokenizer(jwt.SigningMethodHS256)}, nil
}

func (a *TestAuthenticator) Verify(sig string, client *Client) (*TokenClaims, error) {
	return a.Tokenizer.Parse(sig, a.Key)
}

func (a *TestAuthenticator) Authenticate(username, password string, client *Client) (*TokenClaims, error) {
	iat := time.Now()
	exp := iat.Add(1 * time.Hour)
	tc := NewTokenClaims(RoleIdentity, iat, exp)

	tc.Issuer = a.URL.String()
	tc.Subject = username
	tc.Audience = client.ID
	return tc, nil
}

var testProvider *Provider

type MemoryStore struct {
	*sync.Mutex
	authz     map[string]*Authorization
	clients   map[string]*Client
	tokens    map[string]*TokenClaims
	blacklist map[string]bool
}

func NewMemoryStore() (*MemoryStore, error) {
	return &MemoryStore{
		&sync.Mutex{},
		make(map[string]*Authorization, 0),
		make(map[string]*Client, 0),
		make(map[string]*TokenClaims, 0),
		make(map[string]bool, 0),
	}, nil
}

func (s *MemoryStore) CreateClient(c *Client) error {
	s.Lock()
	defer s.Unlock()
	s.clients[c.ID] = c
	return nil
}

func (s *MemoryStore) FetchClient(cid string) (*Client, error) {
	return s.clients[cid], nil
}

func (s *MemoryStore) DeleteClient(cid string) error {
	s.Lock()
	defer s.Unlock()
	delete(s.clients, cid)
	return nil
}

func (s *MemoryStore) BlacklistToken(jti string) error {
	s.Lock()
	defer s.Unlock()
	s.blacklist[jti] = true
	return nil
}

func (s *MemoryStore) TokenBlacklisted(jti string) (bool, error) {
	return s.blacklist[jti], nil
}

func (s *MemoryStore) StoreAuthorization(a *Authorization) error {
	s.Lock()
	defer s.Unlock()
	s.authz[fmt.Sprintf("%s:%s", a.CID, a.UID)] = a
	return nil
}

func (s *MemoryStore) FetchAuthorization(cid, uid string) (*Authorization, error) {
	return s.authz[fmt.Sprintf("%s:%s", cid, uid)], nil
}

func init() {
	authz, err := ParseURL("https://authz.example.com")
	if err != nil {
		panic(err)
	}
	authn, err := ParseURL("https://authn.example.com")
	if err != nil {
		panic(err)
	}
	a, err := NewTestAuthenticator(authn)
	if err != nil {
		panic(err)
	}
	s, err := NewMemoryStore()
	if err != nil {
		panic(err)
	}

	testProvider = NewProvider(authz, a, s)
}
