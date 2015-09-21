package ohauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"
)

// possible values for client status
const (
	ClientActive  = "active"
	ClientRevoked = "revoked"
)

// Client defines an OAuth 2.0 client
type Client struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Secret      string `json:"secret"`

	// GrantType defines the allowed flow the client may use
	GrantType   string     `json:"grantType"`
	RedirectURI *StrictURL `json:"redirectURI"`
	Scope       Scope      `json:"scope"`
	Status      string     `json:"status"`
	Created     time.Time  `json:"created"`

	// Keys are used with a Tokenizer to sign and verify codes and tokens
	Keys *ClientKeys `json:"keys"`
}

// NewClient creates a default client with randomly generated id, secret and keys.
// The default client's scope is empty initially as well.
func NewClient(displayName string, grantType string) *Client {
	return &Client{
		ID:          randID(),
		DisplayName: displayName,
		GrantType:   grantType,
		Created:     time.Now(),
		Secret:      base64.URLEncoding.EncodeToString(randBytes(30)),
		Keys:        NewClientKeys(),
		Scope:       ParseScope(""),
	}
}

// ClientKeys are used in conjuction with Tokenizers to sign and verify codes
// and tokens
type ClientKeys struct {
	Sign   []byte `json:"sign"`
	Verify []byte `json:"verify"`
}

// NewClientKeys creates random pair of private/public keys using RSA 2048
func NewClientKeys() *ClientKeys {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publickey := &privatekey.PublicKey

	priv := x509.MarshalPKCS1PrivateKey(privatekey)
	pub, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		panic(err)
	}

	pempriv := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: priv,
	})
	pempub := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pub,
	})

	return &ClientKeys{pempriv, pempub}
}

// Authorization is used to record a resource owner's approval of a client's
// authorization request when using the Authorization Code and Implicit grant
// types
type Authorization struct {
	CID     string    `json:"cid"`
	UID     string    `json:"uid"`
	Scope   Scope     `json:"scope"`
	Active  bool      `json:"active"`
	Created time.Time `json:"created"`
}

// NewAuthorization initialises an authorization with a specified client id,
// resource owner id and scope that may be saved to a store.
func NewAuthorization(cid, uid string, scope Scope) *Authorization {
	return &Authorization{cid, uid, scope, true, time.Now()}
}
