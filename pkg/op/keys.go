package op

import (
	"context"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
)

type KeyProvider interface {
	KeySet(context.Context) ([]Key, error)
}

func keysHandler(k KeyProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Keys(w, r, k)
	}
}

func Keys(w http.ResponseWriter, r *http.Request, k KeyProvider) {
	ctx, span := tracer.Start(r.Context(), "Keys")
	r = r.WithContext(ctx)
	defer span.End()

	keySet, err := k.KeySet(r.Context())
	if err != nil {
		httphelper.MarshalJSONWithStatus(w, err, http.StatusInternalServerError)
		return
	}
	httphelper.MarshalJSON(w, jsonWebKeySet(keySet))
}

func jsonWebKeySet(keys []Key) *jose.JSONWebKeySet {
	webKeys := make([]jose.JSONWebKey, len(keys))
	for i, key := range keys {
		webKeys[i] = jose.JSONWebKey{
			KeyID:     key.ID(),
			Algorithm: string(key.Algorithm()),
			Use:       key.Use(),
			Key:       key.Key(),
		}
	}
	return &jose.JSONWebKeySet{Keys: webKeys}
}
