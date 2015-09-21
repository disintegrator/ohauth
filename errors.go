package ohauth

import (
	"fmt"
	"net/url"
)

// Error defines an OAuth error with fields specified in rfc6749
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// NewError creates a populated error instance
func NewError(ec, desc string) *Error {
	return &Error{ec, desc}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s - %s", e.Code, e.Description)
}

// Values returns a representation of an Error that can be used as query
// parameters in a redirect uri
func (e *Error) Values() url.Values {
	v := url.Values{}
	v.Set("error", e.Code)
	v.Set("error_description", e.Description)
	return v
}

// Error codes as specified throughout rfc6749
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

// Common errors that can occur while processing authorization and token
// requests
var (
	ErrClientNotFound        = NewError(InvalidClient, "client not found")
	ErrScopeNotAllowed       = NewError(InvalidScope, "client cannot offer requested scope")
	ErrWrongGrant            = NewError(InvalidRequest, "client cannot use specified grant type")
	ErrInvalidGrant          = NewError(InvalidRequest, "invalid grant type")
	ErrUnexpected            = NewError(ServerError, "unexpected error occured")
	ErrUnsupportResponseType = NewError(UnsupportedResponseType, "unsupported response type")
	ErrBadRedirect           = NewError(InvalidRequest, "invalid redirect uri")
	ErrAccessDenied          = NewError(AccessDenied, "access denied")
	ErrUnauthorized          = NewError(UnauthorizedClient, "unauthorized client")
	ErrCodeUsed              = NewError(InvalidRequest, "authorization code has already been used")
)
