package op

import (
	"errors"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/caos/oidc/pkg/utils"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
)

type Exchanger interface {
	Storage() Storage
	Decoder() *schema.Decoder
	Signer() Signer
}

func CodeExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	err := r.ParseForm()
	if err != nil {
		ExchangeRequestError(w, r, ErrInvalidRequest("error parsing form"))
		return
	}
	tokenReq := new(oidc.AccessTokenRequest)

	err = exchanger.Decoder().Decode(tokenReq, r.Form)
	if err != nil {
		ExchangeRequestError(w, r, ErrInvalidRequest("error decoding form"))
		return
	}
	if tokenReq.Code == "" {
		ExchangeRequestError(w, r, ErrInvalidRequest("code missing"))
		return
	}

	client, err := AuthorizeClient(r, tokenReq, exchanger.Storage())
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	authReq, err := exchanger.Storage().AuthRequestByCode(client, tokenReq.Code, tokenReq.RedirectURI)
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	err = exchanger.Storage().DeleteAuthRequestAndCode(authReq.GetID(), tokenReq.Code)
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	accessToken, err := CreateAccessToken()
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	idToken, err := CreateIDToken("", authReq, "", time.Now(), time.Now(), "", exchanger.Signer())
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}

	resp := &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
	}
	utils.MarshalJSON(w, resp)
}

func CreateAccessToken() (string, error) {
	return "accessToken", nil
}

func CreateIDToken(issuer string, authReq AuthRequest, sub string, exp, authTime time.Time, accessToken string, signer Signer) (string, error) {
	var err error
	claims := &oidc.IDTokenClaims{
		Issuer:                              issuer,
		Subject:                             authReq.GetSubject(),
		Audiences:                           authReq.GetAudience(),
		Expiration:                          exp,
		IssuedAt:                            time.Now().UTC(),
		AuthTime:                            authTime,
		Nonce:                               authReq.GetNonce(),
		AuthenticationContextClassReference: authReq.GetACR(),
		AuthenticationMethodsReferences:     authReq.GetAMR(),
		AuthorizedParty:                     authReq.GetClientID(),
	}
	if accessToken != "" {
		var alg jose.SignatureAlgorithm
		claims.AccessTokenHash, err = oidc.AccessTokenHash(accessToken, alg) //TODO: alg
		if err != nil {
			return "", err
		}
	}

	return signer.SignIDToken(claims)
}

func AuthorizeClient(r *http.Request, tokenReq *oidc.AccessTokenRequest, storage Storage) (Client, error) {
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