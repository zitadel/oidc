package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
)

type errorType string

const (
	InvalidRequest       errorType = "invalid_request"
	InvalidScope         errorType = "invalid_scope"
	InvalidClient        errorType = "invalid_client"
	InvalidGrant         errorType = "invalid_grant"
	UnauthorizedClient   errorType = "unauthorized_client"
	UnsupportedGrantType errorType = "unsupported_grant_type"
	ServerError          errorType = "server_error"
	InteractionRequired  errorType = "interaction_required"
	LoginRequired        errorType = "login_required"
	RequestNotSupported  errorType = "request_not_supported"

	// Additional error codes as defined in
	// https://www.rfc-editor.org/rfc/rfc8628#section-3.5
	// Device Access Token Response
	AuthorizationPending errorType = "authorization_pending"
	SlowDown             errorType = "slow_down"
	AccessDenied         errorType = "access_denied"
	ExpiredToken         errorType = "expired_token"

	// InvalidTarget error is returned by Token Exchange if
	// the requested target or audience is invalid.
	// [RFC 8693, Section 2.2.2: Error Response](https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2)
	InvalidTarget errorType = "invalid_target"
)

var (
	ErrInvalidRequest = func() *Error {
		return &Error{
			ErrorType: InvalidRequest,
		}
	}
	ErrInvalidRequestRedirectURI = func() *Error {
		return &Error{
			ErrorType:        InvalidRequest,
			redirectDisabled: true,
		}
	}
	ErrInvalidScope = func() *Error {
		return &Error{
			ErrorType: InvalidScope,
		}
	}
	ErrInvalidClient = func() *Error {
		return &Error{
			ErrorType: InvalidClient,
		}
	}
	ErrInvalidGrant = func() *Error {
		return &Error{
			ErrorType: InvalidGrant,
		}
	}
	ErrUnauthorizedClient = func() *Error {
		return &Error{
			ErrorType: UnauthorizedClient,
		}
	}
	ErrUnsupportedGrantType = func() *Error {
		return &Error{
			ErrorType: UnsupportedGrantType,
		}
	}
	ErrServerError = func() *Error {
		return &Error{
			ErrorType: ServerError,
		}
	}
	ErrInteractionRequired = func() *Error {
		return &Error{
			ErrorType: InteractionRequired,
		}
	}
	ErrLoginRequired = func() *Error {
		return &Error{
			ErrorType: LoginRequired,
		}
	}
	ErrRequestNotSupported = func() *Error {
		return &Error{
			ErrorType: RequestNotSupported,
		}
	}

	// Device Access Token errors:
	ErrAuthorizationPending = func() *Error {
		return &Error{
			ErrorType:   AuthorizationPending,
			Description: "The client SHOULD repeat the access token request to the token endpoint, after interval from device authorization response.",
		}
	}
	ErrSlowDown = func() *Error {
		return &Error{
			ErrorType:   SlowDown,
			Description: "Polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.",
		}
	}
	ErrAccessDenied = func() *Error {
		return &Error{
			ErrorType:   AccessDenied,
			Description: "The authorization request was denied.",
		}
	}
	ErrExpiredDeviceCode = func() *Error {
		return &Error{
			ErrorType:   ExpiredToken,
			Description: "The \"device_code\" has expired.",
		}
	}

	// Token exchange error
	ErrInvalidTarget = func() *Error {
		return &Error{
			ErrorType:   InvalidTarget,
			Description: "The requested audience or target is invalid.",
		}
	}
)

type Error struct {
	Parent           error     `json:"-" schema:"-"`
	ErrorType        errorType `json:"error" schema:"error"`
	Description      string    `json:"error_description,omitempty" schema:"error_description,omitempty"`
	State            string    `json:"state,omitempty" schema:"state,omitempty"`
	redirectDisabled bool      `schema:"-"`
	returnParent     bool      `schema:"-"`
}

func (e *Error) MarshalJSON() ([]byte, error) {
	m := struct {
		Error            errorType `json:"error"`
		ErrorDescription string    `json:"error_description,omitempty"`
		State            string    `json:"state,omitempty"`
		Parent           string    `json:"parent,omitempty"`
	}{
		Error:            e.ErrorType,
		ErrorDescription: e.Description,
		State:            e.State,
	}
	if e.returnParent {
		m.Parent = e.Parent.Error()
	}
	return json.Marshal(m)
}

func (e *Error) Error() string {
	message := "ErrorType=" + string(e.ErrorType)
	if e.Description != "" {
		message += " Description=" + e.Description
	}
	if e.Parent != nil {
		message += " Parent=" + e.Parent.Error()
	}
	return message
}

func (e *Error) Unwrap() error {
	return e.Parent
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.ErrorType == t.ErrorType &&
		(e.Description == t.Description || t.Description == "") &&
		(e.State == t.State || t.State == "")
}

func (e *Error) WithParent(err error) *Error {
	e.Parent = err
	return e
}

// WithReturnParentToClient allows returning the set parent error to the HTTP client.
// Currently it only supports setting the parent inside JSON responses, not redirect URLs.
// As Go errors don't unmarshal well, only the marshaller is implemented for the moment.
//
// Warning: parent errors may contain sensitive data or unwanted details about the server status.
// Also, the `parent` field is not a standard error field and might confuse certain clients
// that require fully compliant responses.
func (e *Error) WithReturnParentToClient(b bool) *Error {
	e.returnParent = b
	return e
}

func (e *Error) WithDescription(desc string, args ...any) *Error {
	e.Description = fmt.Sprintf(desc, args...)
	return e
}

func (e *Error) IsRedirectDisabled() bool {
	return e.redirectDisabled
}

// DefaultToServerError checks if the error is an Error
// if not the provided error will be wrapped into a ServerError
func DefaultToServerError(err error, description string) *Error {
	oauth := new(Error)
	if ok := errors.As(err, &oauth); !ok {
		oauth.ErrorType = ServerError
		oauth.Description = description
		oauth.Parent = err
	}
	return oauth
}

func (e *Error) LogLevel() slog.Level {
	level := slog.LevelWarn
	if e.ErrorType == ServerError {
		level = slog.LevelError
	}
	if e.ErrorType == AuthorizationPending {
		level = slog.LevelInfo
	}
	return level
}

func (e *Error) LogValue() slog.Value {
	attrs := make([]slog.Attr, 0, 5)
	if e.Parent != nil {
		attrs = append(attrs, slog.Any("parent", e.Parent))
	}
	if e.Description != "" {
		attrs = append(attrs, slog.String("description", e.Description))
	}
	if e.ErrorType != "" {
		attrs = append(attrs, slog.String("type", string(e.ErrorType)))
	}
	if e.State != "" {
		attrs = append(attrs, slog.String("state", e.State))
	}
	if e.redirectDisabled {
		attrs = append(attrs, slog.Bool("redirect_disabled", e.redirectDisabled))
	}
	return slog.GroupValue(attrs...)
}
