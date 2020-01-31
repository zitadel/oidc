package op

import (
	"net/http"

	"github.com/caos/oidc/pkg/utils"
)

type KeyProvider interface {
	Storage() Storage
}

func Keys(w http.ResponseWriter, r *http.Request, k KeyProvider) {
	keySet, err := k.Storage().GetKeySet(r.Context())
	if err != nil {

	}
	utils.MarshalJSON(w, keySet)
}
