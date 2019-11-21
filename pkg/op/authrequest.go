package server

import (
	"errors"
	"net/http"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
)

func ParseAuthRequest(w http.ResponseWriter, r *http.Request) (*oidc.AuthRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, errors.New("Unimplemented") //TODO: impl
	}
	authReq := new(oidc.AuthRequest)

	//TODO:
	d := schema.NewDecoder()
	d.IgnoreUnknownKeys(true)

	err = d.Decode(authReq, r.Form)
	return authReq, err
}

func ValidateAuthRequest(authRequest *oidc.AuthRequest) error {
	return errors.New("Unimplemented") //TODO: impl https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.2
}
