package op

import (
	"context"
	"errors"
	"net/http"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/oidc/grants/tokenexchange"
	"github.com/caos/oidc/pkg/utils"
)

type Exchanger interface {
	Issuer() string
	Storage() Storage
	Decoder() utils.Decoder
	Signer() Signer
	Crypto() Crypto
	AuthMethodPostSupported() bool
	GrantTypeTokenExchangeSupported() bool
	GrantTypeJWTAuthorizationSupported() bool
}

type JWTAuthorizationGrantExchanger interface {
	Exchanger
	JWTProfileVerifier() JWTProfileVerifier
}

func tokenHandler(exchanger Exchanger) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.FormValue("grant_type") {
		case string(oidc.GrantTypeCode):
			CodeExchange(w, r, exchanger)
			return
		case string(oidc.GrantTypeBearer):
			if ex, ok := exchanger.(JWTAuthorizationGrantExchanger); ok && exchanger.GrantTypeJWTAuthorizationSupported() {
				JWTProfile(w, r, ex)
				return
			}
		case string(oidc.GrantTypeTokenExchange):
			if exchanger.GrantTypeTokenExchangeSupported() {
				TokenExchange(w, r, exchanger)
				return
			}
		case "":
			RequestError(w, r, ErrInvalidRequest("grant_type missing"))
			return
		}
		RequestError(w, r, ErrInvalidRequest("grant_type not supported"))
	}
}

func CodeExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	tokenReq, err := ParseAccessTokenRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err)
	}
	if tokenReq.Code == "" {
		RequestError(w, r, ErrInvalidRequest("code missing"))
		return
	}
	authReq, client, err := ValidateAccessTokenRequest(r.Context(), tokenReq, exchanger)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	resp, err := CreateTokenResponse(r.Context(), authReq, client, exchanger, true, tokenReq.Code)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	utils.MarshalJSON(w, resp)
}

func ParseAccessTokenRequest(r *http.Request, decoder utils.Decoder) (*oidc.AccessTokenRequest, error) {
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

func ValidateAccessTokenRequest(ctx context.Context, tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (AuthRequest, Client, error) {
	authReq, client, err := AuthorizeClient(ctx, tokenReq, exchanger)
	if err != nil {
		return nil, nil, err
	}
	if client.GetID() != authReq.GetClientID() {
		return nil, nil, ErrInvalidRequest("invalid auth code")
	}
	if tokenReq.RedirectURI != authReq.GetRedirectURI() {
		return nil, nil, ErrInvalidRequest("redirect_uri does no correspond")
	}
	return authReq, client, nil
}

func AuthorizeClient(ctx context.Context, tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (AuthRequest, Client, error) {
	client, err := exchanger.Storage().GetClientByClientID(ctx, tokenReq.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if client.AuthMethod() == AuthMethodNone {
		authReq, err := AuthorizeCodeChallenge(ctx, tokenReq, exchanger)
		return authReq, client, err
	}
	if client.AuthMethod() == AuthMethodPost && !exchanger.AuthMethodPostSupported() {
		return nil, nil, errors.New("basic not supported")
	}
	err = AuthorizeClientIDSecret(ctx, tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage())
	if err != nil {
		return nil, nil, err
	}
	authReq, err := exchanger.Storage().AuthRequestByCode(ctx, tokenReq.Code)
	if err != nil {
		return nil, nil, ErrInvalidRequest("invalid code")
	}
	return authReq, client, nil
}

func AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string, storage OPStorage) error {
	return storage.AuthorizeClientIDSecret(ctx, clientID, clientSecret)
}

func AuthorizeCodeChallenge(ctx context.Context, tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (AuthRequest, error) {
	if tokenReq.CodeVerifier == "" {
		return nil, ErrInvalidRequest("code_challenge required")
	}
	authReq, err := exchanger.Storage().AuthRequestByCode(ctx, tokenReq.Code)
	if err != nil {
		return nil, ErrInvalidRequest("invalid code")
	}
	if !oidc.VerifyCodeChallenge(authReq.GetCodeChallenge(), tokenReq.CodeVerifier) {
		return nil, ErrInvalidRequest("code_challenge invalid")
	}
	return authReq, nil
}

func JWTProfile(w http.ResponseWriter, r *http.Request, exchanger JWTAuthorizationGrantExchanger) {
	profileRequest, err := ParseJWTProfileRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err)
	}

	tokenRequest, err := VerifyJWTAssertion(r.Context(), profileRequest, exchanger.JWTProfileVerifier())
	if err != nil {
		RequestError(w, r, err)
		return
	}

	resp, err := CreateJWTTokenResponse(r.Context(), tokenRequest, exchanger)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	utils.MarshalJSON(w, resp)
}

func ParseJWTProfileRequest(r *http.Request, decoder utils.Decoder) (*tokenexchange.JWTProfileRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, ErrInvalidRequest("error parsing form")
	}
	tokenReq := new(tokenexchange.JWTProfileRequest)
	err = decoder.Decode(tokenReq, r.Form)
	if err != nil {
		return nil, ErrInvalidRequest("error decoding form")
	}
	return tokenReq, nil
}

func TokenExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	tokenRequest, err := ParseTokenExchangeRequest(w, r)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	err = ValidateTokenExchangeRequest(tokenRequest, exchanger.Storage())
	if err != nil {
		RequestError(w, r, err)
		return
	}
}

func ParseTokenExchangeRequest(w http.ResponseWriter, r *http.Request) (oidc.TokenRequest, error) {
	return nil, errors.New("Unimplemented") //TODO: impl
}

func ValidateTokenExchangeRequest(tokenReq oidc.TokenRequest, storage Storage) error {
	return errors.New("Unimplemented") //TODO: impl
}
