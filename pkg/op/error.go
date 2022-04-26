package op

import (
	"net/http"

	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

type ErrAuthRequest interface {
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetState() string
}

func AuthRequestError(w http.ResponseWriter, r *http.Request, authReq ErrAuthRequest, err error, encoder httphelper.Encoder) {
	if authReq == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e := oidc.DefaultToServerError(err, err.Error())
	if authReq.GetRedirectURI() == "" || e.IsRedirectDisabled() {
		http.Error(w, e.Description, http.StatusBadRequest)
		return
	}
	e.State = authReq.GetState()
	var responseMode oidc.ResponseMode
	if rm, ok := authReq.(interface{ GetResponseMode() oidc.ResponseMode }); ok {
		responseMode = rm.GetResponseMode()
	}
	url, err := AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), responseMode, e, encoder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func RequestError(w http.ResponseWriter, r *http.Request, err error) {
	e := oidc.DefaultToServerError(err, err.Error())
	status := http.StatusBadRequest
	if e.ErrorType == oidc.InvalidClient {
		status = 401
	}
	httphelper.MarshalJSONWithStatus(w, e, status)
}
