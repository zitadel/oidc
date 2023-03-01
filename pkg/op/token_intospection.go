package op

import (
	"context"
	"errors"
	"net/http"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type Introspector interface {
	Decoder() httphelper.Decoder
	Crypto() Crypto
	Storage() Storage
	AccessTokenVerifier(context.Context) AccessTokenVerifier
}

type IntrospectorJWTProfile interface {
	Introspector
	JWTProfileVerifier(context.Context) JWTProfileVerifier
}

func introspectionHandler(introspector Introspector) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Introspect(w, r, introspector)
	}
}

func Introspect(w http.ResponseWriter, r *http.Request, introspector Introspector) {
	response := oidc.NewIntrospectionResponse()
	token, clientID, err := ParseTokenIntrospectionRequest(r, introspector)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	tokenID, subject, ok := getTokenIDAndSubject(r.Context(), introspector, token)
	if !ok {
		httphelper.MarshalJSON(w, response)
		return
	}
	err = introspector.Storage().SetIntrospectionFromToken(r.Context(), response, tokenID, subject, clientID)
	if err != nil {
		httphelper.MarshalJSON(w, response)
		return
	}
	response.SetActive(true)
	httphelper.MarshalJSON(w, response)
}

func ParseTokenIntrospectionRequest(r *http.Request, introspector Introspector) (token, clientID string, err error) {
	clientID, authenticated, err := ClientIDFromRequest(r, introspector)
	if err != nil {
		return "", "", err
	}
	if !authenticated {
		return "", "", oidc.ErrInvalidClient().WithParent(ErrNoClientCredentials)
	}

	req := new(oidc.IntrospectionRequest)
	err = introspector.Decoder().Decode(req, r.Form)
	if err != nil {
		return "", "", errors.New("unable to parse request")
	}

	return req.Token, clientID, nil
}
