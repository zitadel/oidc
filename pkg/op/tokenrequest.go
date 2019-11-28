package op

import (
	"errors"
	"net/http"
	"time"

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

func CodeExchange(w http.ResponseWriter, r *http.Request, storage Storage, decoder *schema.Decoder) (*oidc.AccessTokenResponse, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, errors.New("Unimplemented") //TODO: impl
	}
	tokenReq := new(oidc.AccessTokenRequest)

	err = decoder.Decode(tokenReq, r.Form)
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
	idToken, err := CreateIDToken(nil, "", nil)
	if err != nil {

	}

	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
	}, nil
}

func CreateAccessToken() (string, error) {
	return "accessToken", nil
}

type Signer interface {
	Sign(claims *oidc.IDTokenClaims) (string, error)
}

func CreateIDToken(authReq *oidc.AuthRequest, atHash string, signer Signer) (string, error) {
	var issuer, sub, acr string
	var aud, amr []string
	var exp, iat, authTime time.Time

	claims := &oidc.IDTokenClaims{
		Issuer:                              issuer,
		Subject:                             sub,
		Audiences:                           aud,
		Expiration:                          exp,
		IssuedAt:                            iat,
		AuthTime:                            authTime,
		Nonce:                               authReq.Nonce,
		AuthenticationContextClassReference: acr,
		AuthenticationMethodsReferences:     amr,
		AuthorizedParty:                     authReq.ClientID,
		AccessTokenHash:                     atHash,
	}
	return signer.Sign(claims)
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
