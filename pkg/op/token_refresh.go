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
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetScopes() []string
	GetSubject() string
	SetCurrentScopes(scopes oidc.Scopes)
}

//RefreshTokenExchange handles the OAuth 2.0 refresh_token grant, including
//parsing, validating, authorizing the client and finally exchanging the refresh_token for new tokens
func RefreshTokenExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	tokenReq, err := ParseRefreshTokenRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err)
	}
	validatedRequest, client, err := ValidateRefreshTokenRequest(r.Context(), tokenReq, exchanger)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	resp, err := CreateTokenResponse(r.Context(), validatedRequest, client, exchanger, true, "", tokenReq.RefreshToken)
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
	request, client, err := AuthorizeRefreshClient(ctx, tokenReq, exchanger)
	if err != nil {
		return nil, nil, err
	}
	if client.GetID() != request.GetClientID() {
		return nil, nil, ErrInvalidRequest("invalid auth code")
	}
	if err = ValidateRefreshTokenScopes(tokenReq.Scopes, request); err != nil {
		return nil, nil, err
	}
	return request, client, nil
}

//ValidateRefreshTokenScopes validates that requested scope is a subset of the original auth request scope
//it will set the requested scopes as current scopes onto RefreshTokenRequest
//if empty the original scopes will be used
func ValidateRefreshTokenScopes(requestedScopes oidc.Scopes, authRequest RefreshTokenRequest) error {
	if len(requestedScopes) == 0 {
		return nil
	}
	for _, scope := range requestedScopes {
		if !utils.Contains(authRequest.GetScopes(), scope) {
			return errors.New("invalid_scope")
		}
	}
	authRequest.SetCurrentScopes(requestedScopes)
	return nil
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
	if err = AuthorizeClientIDSecret(ctx, tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage()); err != nil {
		return nil, nil, err
	}
	request, err = RefreshTokenRequestByRefreshToken(ctx, exchanger.Storage(), tokenReq.RefreshToken)
	return request, client, err
}

//RefreshTokenRequestByRefreshToken returns the RefreshTokenRequest (data representing the original auth request)
//corresponding to the refresh_token from Storage or an error
func RefreshTokenRequestByRefreshToken(ctx context.Context, storage Storage, refreshToken string) (RefreshTokenRequest, error) {
	request, err := storage.TokenRequestByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidRequest("invalid refreshToken")
	}
	return request, nil
}
