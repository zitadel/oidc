package op

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type Exchanger interface {
	Issuer() string
	IDTokenValidity() time.Duration
	Storage() Storage
	Decoder() *schema.Decoder
	Signer() Signer
	AuthMethodBasicSupported() bool
	AuthMethodPostSupported() bool
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

	authReq, err := exchanger.Storage().AuthRequestByCode(tokenReq.Code)
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	client, err := AuthorizeClient(r, tokenReq, authReq, exchanger)
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	err = ValidateAccessTokenRequest(tokenReq, client, authReq)
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	err = exchanger.Storage().DeleteAuthRequestAndCode(authReq.GetID(), tokenReq.Code)
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	accessToken, exp, err := CreateAccessToken(authReq, exchanger.Signer())
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	idToken, err := CreateIDToken(exchanger.Issuer(), authReq, exchanger.IDTokenValidity(), accessToken, tokenReq.Code, exchanger.Signer())
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}

	resp := &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   exp,
	}
	utils.MarshalJSON(w, resp)
}

func AuthorizeClient(r *http.Request, tokenReq *oidc.AccessTokenRequest, authReq AuthRequest, exchanger Exchanger) (Client, error) {
	if tokenReq.ClientID == "" {
		if !exchanger.AuthMethodBasicSupported() {
			return nil, errors.New("basic not supported")
		}
		clientID, clientSecret, ok := r.BasicAuth()
		if ok {
			return exchanger.Storage().AuthorizeClientIDSecret(clientID, clientSecret)
		}

	}
	if tokenReq.ClientSecret != "" {
		if !exchanger.AuthMethodPostSupported() {
			return nil, errors.New("post not supported")
		}
		return exchanger.Storage().AuthorizeClientIDSecret(tokenReq.ClientID, tokenReq.ClientSecret)
	}
	if tokenReq.CodeVerifier != "" {
		if !authReq.GetCodeChallenge().Verify(tokenReq.CodeVerifier) {
			return nil, ErrInvalidRequest("code_challenge invalid")
		}
		return exchanger.Storage().GetClientByClientID(tokenReq.ClientID)
	}
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ValidateAccessTokenRequest(tokenReq *oidc.AccessTokenRequest, client Client, authReq AuthRequest) error {
	if client.GetID() != authReq.GetClientID() {
		return ErrInvalidRequest("invalid auth code")
	}
	if tokenReq.RedirectURI != authReq.GetRedirectURI() {
		return ErrInvalidRequest("redirect_uri does no correspond")
	}
	return nil
}

func ParseTokenExchangeRequest(w http.ResponseWriter, r *http.Request) (oidc.TokenRequest, error) {
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ValidateTokenExchangeRequest(tokenReq oidc.TokenRequest, storage Storage) error {

	return errors.New("Unimplemented") //TODO: impl
}
