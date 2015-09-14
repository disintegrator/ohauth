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
	ErrClientNotFound        = NewError(InvalidClient, "client not found")
	ErrScopeNotAllowed       = NewError(InvalidScope, "client cannot offer requested scope")
	ErrWrongGrant            = NewError(InvalidRequest, "client cannot use specified grant type")
	ErrInvalidGrant          = NewError(InvalidRequest, "invalid grant type")
	ErrUnexpected            = NewError(ServerError, "unexpected error occured")
	ErrUnsupportResponseType = NewError(UnsupportedResponseType, "unsupported response type")
	ErrBadRedirect           = NewError(InvalidRequest, "invalid redirect uri")
	ErrAccessDenied          = NewError(AccessDenied, "access denied")
)
