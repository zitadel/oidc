package op

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type ErrAuthRequest interface {
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetState() string
}

// LogAuthRequest is an optional interface,
// that allows logging AuthRequest fields.
// If the AuthRequest does not implement this interface,
// no details shall be printed to the logs.
type LogAuthRequest interface {
	ErrAuthRequest
	slog.LogValuer
}

func AuthRequestError(w http.ResponseWriter, r *http.Request, authReq ErrAuthRequest, err error, authorizer Authorizer) {
	e := oidc.DefaultToServerError(err, err.Error())
	logger := authorizer.Logger().With("oidc_error", e)

	if authReq == nil {
		logger.Log(r.Context(), e.LogLevel(), "auth request")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if logAuthReq, ok := authReq.(LogAuthRequest); ok {
		logger = logger.With("auth_request", logAuthReq)
	}

	if authReq.GetRedirectURI() == "" || e.IsRedirectDisabled() {
		logger.Log(r.Context(), e.LogLevel(), "auth request: not redirecting")
		http.Error(w, e.Description, http.StatusBadRequest)
		return
	}
	e.State = authReq.GetState()
	var sessionState string
	authRequestSessionState, ok := authReq.(AuthRequestSessionState)
	if ok {
		sessionState = authRequestSessionState.GetSessionState()
	}
	e.SessionState = sessionState
	var responseMode oidc.ResponseMode
	if rm, ok := authReq.(interface{ GetResponseMode() oidc.ResponseMode }); ok {
		responseMode = rm.GetResponseMode()
	}
	url, err := AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), responseMode, e, authorizer.Encoder())
	if err != nil {
		logger.ErrorContext(r.Context(), "auth response URL", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logger.Log(r.Context(), e.LogLevel(), "auth request")
	http.Redirect(w, r, url, http.StatusFound)
}

func RequestError(w http.ResponseWriter, r *http.Request, err error, logger *slog.Logger) {
	e := oidc.DefaultToServerError(err, err.Error())
	status := http.StatusBadRequest
	if e.ErrorType == oidc.InvalidClient {
		status = http.StatusUnauthorized
	}
	logger.Log(r.Context(), e.LogLevel(), "request error", "oidc_error", e)
	httphelper.MarshalJSONWithStatus(w, e, status)
}

// TryErrorRedirect tries to handle an error by redirecting a client.
// If this attempt fails, an error is returned that must be returned
// to the client instead.
func TryErrorRedirect(ctx context.Context, authReq ErrAuthRequest, parent error, encoder httphelper.Encoder, logger *slog.Logger) (*Redirect, error) {
	e := oidc.DefaultToServerError(parent, parent.Error())
	logger = logger.With("oidc_error", e)

	if authReq == nil {
		logger.Log(ctx, e.LogLevel(), "auth request")
		return nil, AsStatusError(e, http.StatusBadRequest)
	}

	if logAuthReq, ok := authReq.(LogAuthRequest); ok {
		logger = logger.With("auth_request", logAuthReq)
	}

	if authReq.GetRedirectURI() == "" || e.IsRedirectDisabled() {
		logger.Log(ctx, e.LogLevel(), "auth request: not redirecting")
		return nil, AsStatusError(e, http.StatusBadRequest)
	}

	e.State = authReq.GetState()
	var sessionState string
	authRequestSessionState, ok := authReq.(AuthRequestSessionState)
	if ok {
		sessionState = authRequestSessionState.GetSessionState()
	}
	e.SessionState = sessionState
	var responseMode oidc.ResponseMode
	if rm, ok := authReq.(interface{ GetResponseMode() oidc.ResponseMode }); ok {
		responseMode = rm.GetResponseMode()
	}
	url, err := AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), responseMode, e, encoder)
	if err != nil {
		logger.ErrorContext(ctx, "auth response URL", "error", err)
		return nil, AsStatusError(err, http.StatusBadRequest)
	}
	logger.Log(ctx, e.LogLevel(), "auth request redirect", "url", url)
	return NewRedirect(url), nil
}

// StatusError wraps an error with a HTTP status code.
// The status code is passed to the handler's writer.
type StatusError struct {
	parent     error
	statusCode int
}

// NewStatusError sets the parent and statusCode to a new StatusError.
// It is recommended for parent to be an [oidc.Error].
//
// Typically implementations should only use this to signal something
// very specific, like an internal server error.
// If a returned error is not a StatusError, the framework
// will set a statusCode based on what the standard specifies,
// which is [http.StatusBadRequest] for most of the time.
// If the error encountered can described clearly with a [oidc.Error],
// do not use this function, as it might break standard rules!
func NewStatusError(parent error, statusCode int) StatusError {
	return StatusError{
		parent:     parent,
		statusCode: statusCode,
	}
}

// AsStatusError unwraps a StatusError from err
// and returns it unmodified if found.
// If no StatuError was found, a new one is returned
// with statusCode set to it as a default.
func AsStatusError(err error, statusCode int) (target StatusError) {
	if errors.As(err, &target) {
		return target
	}
	return NewStatusError(err, statusCode)
}

func (e StatusError) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(e.statusCode), e.parent.Error())
}

func (e StatusError) Unwrap() error {
	return e.parent
}

func (e StatusError) Is(err error) bool {
	var target StatusError
	if !errors.As(err, &target) {
		return false
	}
	return errors.Is(e.parent, target.parent) &&
		e.statusCode == target.statusCode
}

// WriteError asserts for a [StatusError] containing an [oidc.Error].
// If no `StatusError` is found, the status code will default to [http.StatusBadRequest].
// If no `oidc.Error` was found in the parent, the error type defaults to [oidc.ServerError].
// When there was no `StatusError` and the `oidc.Error` is of type `oidc.ServerError`,
// the status code will be set to [http.StatusInternalServerError]
func WriteError(w http.ResponseWriter, r *http.Request, err error, logger *slog.Logger) {
	var statusError StatusError
	if errors.As(err, &statusError) {
		writeError(w, r,
			oidc.DefaultToServerError(statusError.parent, statusError.parent.Error()),
			statusError.statusCode, logger,
		)
		return
	}
	statusCode := http.StatusBadRequest
	e := oidc.DefaultToServerError(err, err.Error())
	if e.ErrorType == oidc.ServerError {
		statusCode = http.StatusInternalServerError
	}
	writeError(w, r, e, statusCode, logger)
}

func writeError(w http.ResponseWriter, r *http.Request, err *oidc.Error, statusCode int, logger *slog.Logger) {
	logger.Log(r.Context(), err.LogLevel(), "request error", "oidc_error", err, "status_code", statusCode)
	httphelper.MarshalJSONWithStatus(w, err, statusCode)
}
