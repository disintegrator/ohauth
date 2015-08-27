package ohauth

import "time"

type GrantType string

const (
	AuthorizationCode GrantType = "code"
	Implicit          GrantType = "implicit"
	Password          GrantType = "password"
	ClientCredentials GrantType = "client"
)

type ClientStatus string

const (
	Active  ClientStatus = "active"
	Deleted ClientStatus = "deleted"
)

type Client struct {
	ID                string       `json:"id"`
	DisplayName       string       `json:"displayName"`
	Secret            string       `json:"secret"`
	GrantType         GrantType    `json:"grantType"`
	RedirectURI       *URL         `json:"redirectURI"`
	Scope             Scope        `json:"scope"`
	Status            ClientStatus `json:"status"`
	SigningKey        []byte       `json:"-"`
	AuthenticationURI *URL         `json:"authenticationURI"`
	Created           time.Time    `json:"created"`
}

func NewClient(displayName string, gt GrantType) (*Client, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	return &Client{
		ID:          id,
		DisplayName: displayName,
		GrantType:   gt,
		Created:     time.Now(),
	}, nil
}
