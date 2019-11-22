package op

import (
	"errors"
	"net/http"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
	str_utils "github.com/caos/utils/strings"
)

func Authorize(w http.ResponseWriter, r *http.Request, storage Storage) (*oidc.AuthRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, errors.New("Unimplemented") //TODO: impl
	}
	authReq := new(oidc.AuthRequest)

	//TODO:
	d := schema.NewDecoder()
	d.IgnoreUnknownKeys(true)

	err = d.Decode(authReq, r.Form)
	if err != nil {
		return nil, err
	}
	if err = ValidateAuthRequest(authReq, storage); err != nil {
		return nil, err
	}
	err = storage.CreateAuthRequest(authReq)
	if err != nil {
		//TODO: return err
	}
	client, err := storage.GetClientByClientID(authReq.ClientID)
	if err != nil {
		return nil, err
	}
	RedirectToLogin(authReq, client, w, r)
	return nil, nil
}

func ValidateAuthRequest(authReq *oidc.AuthRequest, storage Storage) error {
	if err := ValidateAuthReqScopes(authReq.Scopes); err != nil {
		return err
	}
	if err := ValidateAuthReqRedirectURI(authReq.RedirectURI, authReq.ClientID, storage); err != nil {
		return err
	}
	return nil
	return errors.New("Unimplemented") //TODO: impl https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.2

	// if NeedsExistingSession(authRequest) {
	// 	session, err := storage.CheckSession(authRequest)
	// 	if err != nil {
	// 		//TODO: return err<
	// 	}
	// }
}

func ValidateAuthReqScopes(scopes []string) error {
	if len(scopes) == 0 {
		return errors.New("scope missing")
	}
	if !str_utils.Contains(scopes, oidc.ScopeOpenID) {
		return errors.New("scope openid missing")
	}
	return nil
}

func ValidateAuthReqRedirectURI(uri, client_id string, storage Storage) error {
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

func RedirectToLogin(authReq *oidc.AuthRequest, client oidc.Client, w http.ResponseWriter, r *http.Request) {
	login := client.LoginURL(authReq.ID)
	http.Redirect(w, r, login, http.StatusFound)
}
