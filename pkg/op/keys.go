package op

import (
	"context"
	"net/http"

	"gopkg.in/square/go-jose.v2"

	httphelper "github.com/zitadel/oidc/pkg/http"
)

type KeyProvider interface {
	GetKeySet(context.Context) (*jose.JSONWebKeySet, error)
}

func keysHandler(k KeyProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Keys(w, r, k)
	}
}

func Keys(w http.ResponseWriter, r *http.Request, k KeyProvider) {
	keySet, err := k.GetKeySet(r.Context())
	if err != nil {
		httphelper.MarshalJSONWithStatus(w, err, http.StatusInternalServerError)
		return
	}
	httphelper.MarshalJSON(w, keySet)
}
