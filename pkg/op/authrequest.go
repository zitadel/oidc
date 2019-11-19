package server

import (
	"errors"
	"net/http"

	"github.com/caos/oidc/pkg/oidc"
)

func ParseAuthRequest(w http.ResponseWriter, r *http.Request) (*oidc.AuthRequest, error) {
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ValidateAuthRequest(authRequest *oidc.AuthRequest) error {
	return errors.New("Unimplemented") //TODO: impl https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.2
}
