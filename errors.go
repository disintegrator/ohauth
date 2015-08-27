package ohauth

import "fmt"

type ErrorCode string

const (
	AccessDenied            ErrorCode = "access_denied"
	InvalidClient           ErrorCode = "invalid_client"
	InvalidGrant            ErrorCode = "invalid_grant"
	InvalidRequest          ErrorCode = "invalid_request"
	InvalidScope            ErrorCode = "invalid_scope"
	ServerError             ErrorCode = "server_error"
	TemporarilyUnavailable  ErrorCode = "temporarily_unavailable"
	UnauthorizedClient      ErrorCode = "unauthorized_client"
	UnsupportedGrantType    ErrorCode = "unsupported_grant_type"
	UnsupportedResponseType ErrorCode = "unsupported_response_type"
)

func (ec ErrorCode) DocumentedError(d Documenter, desc string, state string) *Error {
	return &Error{
		ec,
		desc,
		state,
		d.URIForError(ec),
	}
}

type Error struct {
	Code        ErrorCode `json:"error"`
	Description string    `json:"error_description,omitempty"`
	State       string    `json:"state,omitempty"`
	URI         *URL      `json:"error_uri,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s - %s [%s]", e.Code, e.Description, e.URI)
}
