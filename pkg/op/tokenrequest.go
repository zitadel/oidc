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
	AuthMethodPostSupported() bool
}

func CodeExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	tokenReq, err := ParseAccessTokenRequest(r, exchanger.Decoder())
	if err != nil {
		ExchangeRequestError(w, r, err)
	}
	if tokenReq.Code == "" {
		ExchangeRequestError(w, r, ErrInvalidRequest("code missing"))
		return
	}

	authReq, err := ValidateAccessTokenRequest(tokenReq, exchanger)
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

func ParseAccessTokenRequest(r *http.Request, decoder *schema.Decoder) (*oidc.AccessTokenRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, ErrInvalidRequest("error parsing form")
	}
	tokenReq := new(oidc.AccessTokenRequest)
	err = decoder.Decode(tokenReq, r.Form)
	if err != nil {
		return nil, ErrInvalidRequest("error decoding form")
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		tokenReq.ClientID = clientID
		tokenReq.ClientSecret = clientSecret

	}
	return tokenReq, nil
}

func ValidateAccessTokenRequest(tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (AuthRequest, error) {
	authReq, client, err := AuthorizeClient(tokenReq, exchanger)
	if err != nil {
		return nil, err
	}
	if client.GetID() != authReq.GetClientID() {
		return nil, ErrInvalidRequest("invalid auth code")
	}
	if tokenReq.RedirectURI != authReq.GetRedirectURI() {
		return nil, ErrInvalidRequest("redirect_uri does no correspond")
	}
	return authReq, nil
}

func AuthorizeClient(tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (AuthRequest, Client, error) {
	client, err := exchanger.Storage().GetClientByClientID(tokenReq.ClientID)
	if err != nil {
		return nil, nil, err
	}
	switch client.GetAuthMethod() {
	case AuthMethodNone:
		authReq, err := AuthorizeCodeChallenge(tokenReq, exchanger.Storage())
		return authReq, client, err
	case AuthMethodPost:
		if !exchanger.AuthMethodPostSupported() {
			return nil, nil, errors.New("basic not supported")
		}
		err = AuthorizeClientIDSecret(tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage())
	case AuthMethodBasic:
		err = AuthorizeClientIDSecret(tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage())
	default:
		err = AuthorizeClientIDSecret(tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage())
	}
	if err != nil {
		return nil, nil, err
	}
	authReq, err := exchanger.Storage().AuthRequestByCode(tokenReq.Code)
	if err != nil {
		return nil, nil, err
	}
	return authReq, client, nil
}

func AuthorizeClientIDSecret(clientID, clientSecret string, storage OPStorage) error {
	return storage.AuthorizeClientIDSecret(clientID, clientSecret)
}

func AuthorizeCodeChallenge(tokenReq *oidc.AccessTokenRequest, storage AuthStorage) (AuthRequest, error) {
	if tokenReq.CodeVerifier == "" {
		return nil, ErrInvalidRequest("code_challenge required")
	}
	authReq, err := storage.AuthRequestByCode(tokenReq.Code)
	if err != nil {
		return nil, ErrInvalidRequest("invalid code")
	}
	if !authReq.GetCodeChallenge().Verify(tokenReq.CodeVerifier) {
		return nil, ErrInvalidRequest("code_challenge invalid")
	}
	return authReq, nil
}

func TokenExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	tokenRequest, err := ParseTokenExchangeRequest(w, r)
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
	err = ValidateTokenExchangeRequest(tokenRequest, exchanger.Storage())
	if err != nil {
		ExchangeRequestError(w, r, err)
		return
	}
}

func ParseTokenExchangeRequest(w http.ResponseWriter, r *http.Request) (oidc.TokenRequest, error) {
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ValidateTokenExchangeRequest(tokenReq oidc.TokenRequest, storage Storage) error {
	return errors.New("Unimplemented") //TODO: impl
}
