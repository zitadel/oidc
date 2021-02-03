package op

import (
	"errors"
	"net/http"
	"strings"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type Introspector interface {
	Decoder() utils.Decoder
	Crypto() Crypto
	Storage() Storage
	AccessTokenVerifier() AccessTokenVerifier
}

func introspectionHandler(introspector Introspector) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Introspect(w, r, introspector)
	}
}

func Introspect(w http.ResponseWriter, r *http.Request, introspector Introspector) {
	callerToken := r.Header.Get("authorization")
	response := oidc.NewIntrospectionResponse()
	callerToken, callerSubject, ok := getTokenIDAndSubject(r.Context(), introspector, strings.TrimPrefix(callerToken, oidc.PrefixBearer))
	if !ok {
		utils.MarshalJSON(w, response)
		return
	}
	introspectionToken, err := ParseTokenInrospectionRequest(r, introspector.Decoder())
	if err != nil {
		utils.MarshalJSON(w, response)
		return
	}
	tokenID, subject, ok := getTokenIDAndSubject(r.Context(), introspector, introspectionToken)
	if !ok {
		utils.MarshalJSON(w, response)
		return
	}
	err = introspector.Storage().SetIntrospectionFromToken(r.Context(), response, tokenID, subject, callerToken, callerSubject)
	if err != nil {
		utils.MarshalJSON(w, response)
		return
	}
	response.SetActive(true)
	utils.MarshalJSON(w, response)
}

func ParseTokenInrospectionRequest(r *http.Request, decoder utils.Decoder) (string, error) {
	err := r.ParseForm()
	if err != nil {
		return "", errors.New("unable to parse request")
	}
	req := new(oidc.IntrospectionRequest)
	err = decoder.Decode(req, r.Form)
	if err != nil {
		return "", errors.New("unable to parse request")
	}
	return req.Token, nil
}
