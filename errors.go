package ohauth

import (
	"fmt"
	"net/url"
)

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func NewError(ec, desc string) *Error {
	return &Error{ec, desc}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s - %s", e.Code, e.Description)
}

func (e *Error) Values() url.Values {
	v := url.Values{}
	v.Set("error", e.Code)
	v.Set("error_description", e.Description)
	return v
}

const (
	AccessDenied            = "access_denied"
	InvalidClient           = "invalid_client"
	InvalidGrant            = "invalid_grant"
	InvalidRequest          = "invalid_request"
	InvalidScope            = "invalid_scope"
	ServerError             = "server_error"
	TemporarilyUnavailable  = "temporarily_unavailable"
	UnauthorizedClient      = "unauthorized_client"
	UnsupportedGrantType    = "unsupported_grant_type"
	UnsupportedResponseType = "unsupported_response_type"
)

var (
	clientNotFound        = NewError(InvalidClient, "client not found")
	unexpectedError       = NewError(ServerError, "unexpected error occured")
	unsupportResponseType = NewError(UnsupportedResponseType, "unsupported response type")
	badRedirect           = NewError(InvalidRequest, "invalid redirect uri")
	accessDenied          = NewError(AccessDenied, "access denied")
)
