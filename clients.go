package ohauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"
)

const (
	ClientActive  = "active"
	ClientRevoked = "revoked"
)

type Client struct {
	ID          string      `json:"id"`
	DisplayName string      `json:"displayName"`
	Secret      string      `json:"secret"`
	GrantType   string      `json:"grantType"`
	RedirectURI *StrictURL  `json:"redirectURI"`
	Scope       *Scope      `json:"scope"`
	Status      string      `json:"status"`
	Created     time.Time   `json:"created"`
	Keys        *ClientKeys `json:"keys"`
}

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

type ClientKeys struct {
	Sign   []byte `json:"sign"`
	Verify []byte `json:"verify"`
}

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

type Authorization struct {
	CID     string    `json:"cid"`
	UID     string    `json:"uid"`
	Scope   *Scope    `json:"scope"`
	Active  bool      `json:"active"`
	Created time.Time `json:"created"`
}

func NewAuthorization(cid, uid string, scope *Scope) *Authorization {
	return &Authorization{cid, uid, scope, true, time.Now()}
}
