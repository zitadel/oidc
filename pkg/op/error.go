package op

import (
	"net/http"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/exp/slog"
)

type ErrAuthRequest interface {
	slog.LogValuer
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetState() string
}

func AuthRequestError(w http.ResponseWriter, r *http.Request, authReq ErrAuthRequest, err error, authorizer Authorizer) {
	e := oidc.DefaultToServerError(err, err.Error())
	logger := authorizer.Logger().With("oidc_error", e)

	if authReq == nil {
		logger.Log(r.Context(), e.LogLevel(), "auth request nil")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logger = logger.With("authRequest", authReq)

	if authReq.GetRedirectURI() == "" || e.IsRedirectDisabled() {
		logger.Log(r.Context(), e.LogLevel(), "auth request without redirect")
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
	logger.Log(r.Context(), e.LogLevel(), "auth request error")
	http.Redirect(w, r, url, http.StatusFound)
}

func RequestError(w http.ResponseWriter, r *http.Request, err error, logger *slog.Logger) {
	e := oidc.DefaultToServerError(err, err.Error())
	status := http.StatusBadRequest
	if e.ErrorType == oidc.InvalidClient {
		status = 401
	}
	logger.Log(r.Context(), e.LogLevel(), "request error", "oidc_error", e)
	httphelper.MarshalJSONWithStatus(w, e, status)
}
