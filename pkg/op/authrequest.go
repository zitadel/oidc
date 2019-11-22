package op

import (
	"errors"
	"net/http"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
	str_utils "github.com/caos/utils/strings"
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

func ValidateAuthRequest(authRequest *oidc.AuthRequest, storage Storage) error {

	if err := ValidateRedirectURI(authRequest.RedirectURI, authRequest.ClientID, storage); err != nil {
		return err
	}
	return errors.New("Unimplemented") //TODO: impl https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.2

	// if NeedsExistingSession(authRequest) {
	// 	session, err := storage.CheckSession(authRequest)
	// 	if err != nil {
	// 		//TODO: return err
	// 	}
	// }
}

func ValidateRedirectURI(uri, client_id string, storage Storage) error {
	if uri == "" {
		return errors.New("redirect_uri must not be empty") //TODO:
	}
	client, err := storage.GetClientByClientID(client_id)
	if err != nil {
		return err
	}
	if !str_utils.Contains(client.RedirectURIs(), uri) {
		return errors.New("redirect_uri not allowed")
	}
	return nil
}
