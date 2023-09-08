package op

import (
	"context"
	"net/http"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/exp/slog"
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

func TryErrorRedirect(ctx context.Context, authReq ErrAuthRequest, parent error, encoder httphelper.Encoder, logger *slog.Logger) (*Redirect, error) {
	e := oidc.DefaultToServerError(parent, parent.Error())
	logger = logger.With("oidc_error", e)

	if authReq == nil {
		logger.Log(ctx, e.LogLevel(), "auth request")
		return nil, NewStatusError(parent, http.StatusBadRequest)
	}

	if logAuthReq, ok := authReq.(LogAuthRequest); ok {
		logger = logger.With("auth_request", logAuthReq)
	}

	if authReq.GetRedirectURI() == "" || e.IsRedirectDisabled() {
		logger.Log(ctx, e.LogLevel(), "auth request: not redirecting")
		return nil, NewStatusError(parent, http.StatusBadRequest)
	}

	e.State = authReq.GetState()
	var responseMode oidc.ResponseMode
	if rm, ok := authReq.(interface{ GetResponseMode() oidc.ResponseMode }); ok {
		responseMode = rm.GetResponseMode()
	}
	url, err := AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), responseMode, e, encoder)
	if err != nil {
		logger.ErrorContext(ctx, "auth response URL", "error", err)
		return nil, NewStatusError(err, http.StatusBadRequest)
	}
	return NewRedirect(url), nil
}
