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

	client, err := AuthorizeClient(r, tokenReq, exchanger)
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
	idToken, err := CreateIDToken(exchanger.Issuer(), authReq, exchanger.IDTokenValidity(), accessToken, exchanger.Signer())
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

func CreateIDToken(issuer string, authReq AuthRequest, validity time.Duration, accessToken string, signer Signer) (string, error) {
	var err error
	exp := time.Now().UTC().Add(validity)
	claims := &oidc.IDTokenClaims{
		Issuer:                              issuer,
		Subject:                             authReq.GetSubject(),
		Audiences:                           authReq.GetAudience(),
		Expiration:                          exp,
		IssuedAt:                            time.Now().UTC(),
		AuthTime:                            authReq.GetAuthTime(),
		Nonce:                               authReq.GetNonce(),
		AuthenticationContextClassReference: authReq.GetACR(),
		AuthenticationMethodsReferences:     authReq.GetAMR(),
		AuthorizedParty:                     authReq.GetClientID(),
	}
	if accessToken != "" {
		claims.AccessTokenHash, err = oidc.AccessTokenHash(accessToken, signer.SignatureAlgorithm())
		if err != nil {
			return "", err
		}
	}

	return signer.SignIDToken(claims)
}

func AuthorizeClient(r *http.Request, tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (Client, error) {
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
		return exchanger.Storage().AuthorizeClientIDCodeVerifier(tokenReq.ClientID, tokenReq.CodeVerifier)
	}
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ParseTokenExchangeRequest(w http.ResponseWriter, r *http.Request) (oidc.TokenRequest, error) {
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ValidateTokenExchangeRequest(tokenReq oidc.TokenRequest, storage Storage) error {

	return errors.New("Unimplemented") //TODO: impl
}
