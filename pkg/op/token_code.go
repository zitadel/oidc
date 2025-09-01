package op

import (
	"context"
	"net/http"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// CodeExchange handles the OAuth 2.0 authorization_code grant, including
// parsing, validating, authorizing the client and finally exchanging the code for tokens
func CodeExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	ctx, span := tracer.Start(r.Context(), "CodeExchange")
	defer span.End()
	r = r.WithContext(ctx)

	tokenReq, err := ParseAccessTokenRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
	}
	if tokenReq.Code == "" {
		RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("code missing"), exchanger.Logger())
		return
	}
	authReq, client, err := ValidateAccessTokenRequest(r.Context(), tokenReq, exchanger)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	resp, err := CreateTokenResponse(r.Context(), authReq, client, exchanger, true, tokenReq.Code, "")
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	httphelper.MarshalJSON(w, resp)
}

// ParseAccessTokenRequest parsed the http request into a oidc.AccessTokenRequest
func ParseAccessTokenRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.AccessTokenRequest, error) {
	request := new(oidc.AccessTokenRequest)
	err := ParseAuthenticatedTokenRequest(r, decoder, request)
	if err != nil {
		return nil, err
	}
	return request, nil
}

// ValidateAccessTokenRequest validates the token request parameters including authorization check of the client
// and returns the previous created auth request corresponding to the auth code
func ValidateAccessTokenRequest(ctx context.Context, tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (AuthRequest, Client, error) {
	ctx, span := tracer.Start(ctx, "ValidateAccessTokenRequest")
	defer span.End()

	authReq, client, err := AuthorizeCodeClient(ctx, tokenReq, exchanger)
	if err != nil {
		return nil, nil, err
	}
	if client.GetID() != authReq.GetClientID() {
		return nil, nil, oidc.ErrInvalidGrant()
	}
	if !ValidateGrantType(client, oidc.GrantTypeCode) {
		return nil, nil, oidc.ErrUnauthorizedClient().WithDescription("client missing grant type " + string(oidc.GrantTypeCode))
	}
	if tokenReq.RedirectURI != authReq.GetRedirectURI() {
		return nil, nil, oidc.ErrInvalidGrant().WithDescription("redirect_uri does not correspond")
	}
	return authReq, client, nil
}

// AuthorizeCodeClient checks the authorization of the client and that the used method was the one previously registered.
// It than returns the auth request corresponding to the auth code
func AuthorizeCodeClient(ctx context.Context, tokenReq *oidc.AccessTokenRequest, exchanger Exchanger) (request AuthRequest, client Client, err error) {
	ctx, span := tracer.Start(ctx, "AuthorizeCodeClient")
	defer span.End()

	request, err = AuthRequestByCode(ctx, exchanger.Storage(), tokenReq.Code)
	if err != nil {
		return nil, nil, err
	}

	codeChallenge := request.GetCodeChallenge()
	err = AuthorizeCodeChallenge(tokenReq.CodeVerifier, codeChallenge)
	if err != nil {
		return nil, nil, err
	}

	if tokenReq.ClientAssertionType == oidc.ClientAssertionTypeJWTAssertion {
		jwtExchanger, ok := exchanger.(JWTAuthorizationGrantExchanger)
		if !ok || !exchanger.AuthMethodPrivateKeyJWTSupported() {
			return nil, nil, oidc.ErrInvalidClient().WithDescription("auth_method private_key_jwt not supported")
		}
		client, err = AuthorizePrivateJWTKey(ctx, tokenReq.ClientAssertion, jwtExchanger)
		if err != nil {
			return nil, nil, err
		}
		return request, client, err
	}

	client, err = exchanger.Storage().GetClientByClientID(ctx, tokenReq.ClientID)
	if err != nil {
		return nil, nil, oidc.ErrInvalidClient().WithParent(err)
	}
	if client.AuthMethod() == oidc.AuthMethodPrivateKeyJWT {
		return nil, nil, oidc.ErrInvalidClient().WithDescription("private_key_jwt not allowed for this client")
	}
	if client.AuthMethod() == oidc.AuthMethodNone {
		if codeChallenge == nil {
			return nil, nil, oidc.ErrInvalidRequest().WithDescription("PKCE required")
		}
		return request, client, nil
	}
	if client.AuthMethod() == oidc.AuthMethodPost && !exchanger.AuthMethodPostSupported() {
		return nil, nil, oidc.ErrInvalidClient().WithDescription("auth_method post not supported")
	}
	err = AuthorizeClientIDSecret(ctx, tokenReq.ClientID, tokenReq.ClientSecret, exchanger.Storage())
	if err != nil {
		return nil, nil, err
	}

	return request, client, err
}

// AuthRequestByCode returns the AuthRequest previously created from Storage corresponding to the auth code or an error
func AuthRequestByCode(ctx context.Context, storage Storage, code string) (AuthRequest, error) {
	ctx, span := tracer.Start(ctx, "AuthRequestByCode")
	defer span.End()

	authReq, err := storage.AuthRequestByCode(ctx, code)
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid code").WithParent(err)
	}
	return authReq, nil
}
