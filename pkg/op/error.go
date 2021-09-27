package op

import (
	"net/http"

	httphelper "github.com/caos/oidc/pkg/http"
	"github.com/caos/oidc/pkg/oidc"
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
	e := oidc.DefaultToServerError(err, err.Error()) //TODO: desc?
	e.State = authReq.GetState()
	if authReq.GetRedirectURI() == "" || e.IsRedirectDisabled() {
		http.Error(w, e.Description, http.StatusBadRequest)
		return
	}
	params, err := httphelper.URLEncodeResponse(e, encoder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	url := authReq.GetRedirectURI()
	responseType := authReq.GetResponseType()
	if responseType == "" || responseType == oidc.ResponseTypeCode {
		url += "?" + params
	} else {
		url += "#" + params
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func RequestError(w http.ResponseWriter, r *http.Request, err error) {
	e := oidc.DefaultToServerError(err, err.Error()) //TODO: desc?
	status := http.StatusBadRequest
	if e.ErrorType == oidc.InvalidClient {
		status = 401
	}
	httphelper.MarshalJSONWithStatus(w, e, status)
}
