package op

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type RefreshTokenRequest interface {
	//GetID() string
	//GetACR() string
	//GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetScopes() []string
	GetSubject() string
	//GetRefreshToken() string
}

//RefreshTokenExchange handles the OAuth 2.0 refresh_token grant, including
//parsing, validating, authorizing the client and finally exchanging the refresh_token for new tokens
func RefreshTokenExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	tokenReq, err := ParseRefreshTokenRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err)
	}
	authReq, client, err := ValidateRefreshTokenRequest(r.Context(), tokenReq, exchanger)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	resp, err := CreateTokenResponse(r.Context(), authReq, client, exchanger, true, "")
	if err != nil {
		RequestError(w, r, err)
		return
	}
	utils.MarshalJSON(w, resp)
}

//ParseRefreshTokenRequest parsed the http request into a oidc.RefreshTokenRequest
func ParseRefreshTokenRequest(r *http.Request, decoder utils.Decoder) (*oidc.RefreshTokenRequest, error) {
	request := new(oidc.RefreshTokenRequest)
	err := ParseAuthenticatedTokenRequest(r, decoder, request)
	if err != nil {
		return nil, err
	}
	return request, nil
}

//ValidateRefreshTokenRequest validates the refresh_token request parameters including authorization check of the client
//and returns the data representing the original auth request corresponding to the refresh_token
func ValidateRefreshTokenRequest(ctx context.Context, tokenReq *oidc.RefreshTokenRequest, exchanger Exchanger) (RefreshTokenRequest, Client, error) {
	if tokenReq.RefreshToken == "" {
		return nil, nil, ErrInvalidRequest("code missing")
	}
	authReq, client, err := AuthorizeRefreshClient(ctx, tokenReq, exchanger)
	if err != nil {
		return nil, nil, err
	}
	if client.GetID() != authReq.GetClientID() {
		return nil, nil, ErrInvalidRequest("invalid auth code")
	}
	return authReq, client, nil
}

//AuthorizeCodeClient checks the authorization of the client and that the used method was the one previously registered.
//It than returns the data representing the original auth request corresponding to the refresh_token
func AuthorizeRefreshClient(ctx context.Context, tokenReq *oidc.RefreshTokenRequest, exchanger Exchanger) (request RefreshTokenRequest, client Client, err error) {
	if tokenReq.ClientAssertionType == oidc.ClientAssertionTypeJWTAssertion {
		jwtExchanger, ok := exchanger.(JWTAuthorizationGrantExchanger)
		if !ok || !exchanger.AuthMethodPrivateKeyJWTSupported() {
			return nil, nil, errors.New("auth_method private_key_jwt not supported")
		}
		client, err = AuthorizePrivateJWTKey(ctx, tokenReq.ClientAssertion, jwtExchanger)
		if err != nil {
			return nil, nil, err
		}
		request, err = RefreshTokenRequestByRefreshToken(ctx, exchanger.Storage(), tokenReq.RefreshToken)
		return request, client, err
	}
	client, err = exchanger.Storage().GetClientByClientID(ctx, tokenReq.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if client.AuthMethod() == oidc.AuthMethodPrivateKeyJWT {
		return nil, nil, errors.New("invalid_grant")
	}
	if client.AuthMethod() == oidc.AuthMethodNone {
		request, err = RefreshTokenRequestByRefreshToken(ctx, exchanger.Storage(), tokenReq.RefreshToken)
		return request, client, err
	}
	if client.AuthMethod() == oidc.AuthMethodPost && !exchanger.AuthMethodPostSupported() {
		return nil, nil, errors.New("auth_method post not supported")
	}
	err = AuthorizeClientIDSecret(ctx, tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage())
	request, err = RefreshTokenRequestByRefreshToken(ctx, exchanger.Storage(), tokenReq.RefreshToken)
	return request, client, err
}

//RefreshTokenRequestByRefreshToken returns the RefreshTokenRequest (data representing the original auth request)
//corresponding to the refresh_token from Storage or an error
func RefreshTokenRequestByRefreshToken(ctx context.Context, storage Storage, refreshToken string) (RefreshTokenRequest, error) {
	authReq, err := storage.RefreshTokenRequestByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidRequest("invalid refreshToken")
	}
	return authReq, nil
}
