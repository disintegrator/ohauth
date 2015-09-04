package ohauth

import "time"

const (
	ClientActive  = "active"
	ClientRevoked = "revoked"
)

type Client struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName"`
	Secret      string     `json:"secret"`
	GrantType   string     `json:"grantType"`
	RedirectURI *StrictURL `json:"redirectURI"`
	Scope       Scope      `json:"scope"`
	Status      string     `json:"status"`
	Created     time.Time  `json:"created"`
	SigningKey  []byte     `json:"-"`
}

func NewClient(displayName string, grantType string) *Client {
	return &Client{
		ID:          randID(),
		DisplayName: displayName,
		GrantType:   grantType,
		Created:     time.Now(),
	}
}
