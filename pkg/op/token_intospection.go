package op

import (
	"errors"
	"net/http"

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
	//validate authorization

	response := oidc.NewIntrospectionResponse()
	token, err := ParseTokenInrospectionRequest(r, introspector.Decoder())
	if err != nil {
		utils.MarshalJSON(w, response)
		return
	}
	tokenID, subject, ok := getTokenIDAndSubject(r.Context(), introspector, token)
	if !ok {
		utils.MarshalJSON(w, response)
		return
	}
	err = introspector.Storage().SetUserinfoFromToken(r.Context(), response, tokenID, subject, r.Header.Get("origin"))
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
