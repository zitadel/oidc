package oidc

import (
	"errors"
	"fmt"
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
)

type Error struct {
	Parent           error     `json:"-" schema:"-"`
	ErrorType        errorType `json:"error" schema:"error"`
	Description      string    `json:"error_description,omitempty" schema:"error_description,omitempty"`
	State            string    `json:"state,omitempty" schema:"state,omitempty"`
	redirectDisabled bool      `schema:"-"`
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
