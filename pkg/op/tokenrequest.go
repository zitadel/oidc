package op

import (
	"errors"
	"net/http"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
)

// func ParseTokenRequest(w http.ResponseWriter, r *http.Request) (oidc.TokenRequest, error) {
// 	reqType := r.FormValue("grant_type")
// 	if reqType == "" {
// 		return nil, errors.New("grant_type missing") //TODO: impl
// 	}
// 	if reqType == string(oidc.GrantTypeCode) {
// 		return ParseAccessTokenRequest(w, r)
// 	}
// 	return ParseTokenExchangeRequest(w, r)
// }

func CodeExchange(w http.ResponseWriter, r *http.Request, storage Storage) (*oidc.AccessTokenResponse, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, errors.New("Unimplemented") //TODO: impl
	}
	tokenReq := new(oidc.AccessTokenRequest)

	//TODO:
	d := schema.NewDecoder()
	d.IgnoreUnknownKeys(true)

	err = d.Decode(tokenReq, r.Form)
	if err != nil {
		return nil, err
	}
	if tokenReq.Code == "" {
		return nil, errors.New("code missing")
	}

	client, err := AuthorizeClient(r, tokenReq, storage)
	if err != nil {
		return nil, err
	}
	authReq, err := storage.AuthRequestByCode(client, tokenReq.Code, tokenReq.RedirectURI)
	if err != nil {

	}
	err = storage.DeleteAuthRequestAndCode(authReq.ID, tokenReq.Code)
	if err != nil {

	}
	accessToken, err := CreateAccessToken()
	if err != nil {

	}
	idToken, err := CreateIDToken()
	if err != nil {

	}

	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
	}, nil
}

func CreateAccessToken() (string, error) {
	return "", nil
}
func CreateIDToken() (string, error) {
	return "", nil
}

func AuthorizeClient(r *http.Request, tokenReq *oidc.AccessTokenRequest, storage Storage) (oidc.Client, error) {
	if tokenReq.ClientID == "" {
		clientID, clientSecret, ok := r.BasicAuth()
		if ok {
			return storage.AuthorizeClientIDSecret(clientID, clientSecret)
		}

	}
	if tokenReq.ClientSecret != "" {
		return storage.AuthorizeClientIDSecret(tokenReq.ClientID, tokenReq.ClientSecret)
	}
	if tokenReq.CodeVerifier != "" {
		return storage.AuthorizeClientIDCodeVerifier(tokenReq.ClientID, tokenReq.CodeVerifier)
	}
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ParseTokenExchangeRequest(w http.ResponseWriter, r *http.Request) (oidc.TokenRequest, error) {
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ValidateTokenExchangeRequest(tokenReq oidc.TokenRequest, storage Storage) error {

	return errors.New("Unimplemented") //TODO: impl
}
