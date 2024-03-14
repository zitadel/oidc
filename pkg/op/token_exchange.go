package op

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type TokenExchangeRequest interface {
	GetAMR() []string
	GetAudience() []string
	GetResourses() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetScopes() []string
	GetSubject() string
	GetRequestedTokenType() oidc.TokenType

	GetExchangeSubject() string
	GetExchangeSubjectTokenType() oidc.TokenType
	GetExchangeSubjectTokenIDOrToken() string
	GetExchangeSubjectTokenClaims() map[string]any

	GetExchangeActor() string
	GetExchangeActorTokenType() oidc.TokenType
	GetExchangeActorTokenIDOrToken() string
	GetExchangeActorTokenClaims() map[string]any

	SetCurrentScopes(scopes []string)
	SetRequestedTokenType(tt oidc.TokenType)
	SetSubject(subject string)
}

type tokenExchangeRequest struct {
	exchangeSubjectTokenIDOrToken string
	exchangeSubjectTokenType      oidc.TokenType
	exchangeSubject               string
	exchangeSubjectTokenClaims    map[string]any

	exchangeActorTokenIDOrToken string
	exchangeActorTokenType      oidc.TokenType
	exchangeActor               string
	exchangeActorTokenClaims    map[string]any

	resource           []string
	audience           oidc.Audience
	scopes             oidc.SpaceDelimitedArray
	requestedTokenType oidc.TokenType
	clientID           string
	authTime           time.Time
	subject            string
}

func (r *tokenExchangeRequest) GetAMR() []string {
	return []string{}
}

func (r *tokenExchangeRequest) GetAudience() []string {
	return r.audience
}

func (r *tokenExchangeRequest) GetResourses() []string {
	return r.resource
}

func (r *tokenExchangeRequest) GetAuthTime() time.Time {
	return r.authTime
}

func (r *tokenExchangeRequest) GetClientID() string {
	return r.clientID
}

func (r *tokenExchangeRequest) GetScopes() []string {
	return r.scopes
}

func (r *tokenExchangeRequest) GetRequestedTokenType() oidc.TokenType {
	return r.requestedTokenType
}

func (r *tokenExchangeRequest) GetExchangeSubject() string {
	return r.exchangeSubject
}

func (r *tokenExchangeRequest) GetExchangeSubjectTokenType() oidc.TokenType {
	return r.exchangeSubjectTokenType
}

func (r *tokenExchangeRequest) GetExchangeSubjectTokenIDOrToken() string {
	return r.exchangeSubjectTokenIDOrToken
}

func (r *tokenExchangeRequest) GetExchangeSubjectTokenClaims() map[string]any {
	return r.exchangeSubjectTokenClaims
}

func (r *tokenExchangeRequest) GetExchangeActor() string {
	return r.exchangeActor
}

func (r *tokenExchangeRequest) GetExchangeActorTokenType() oidc.TokenType {
	return r.exchangeActorTokenType
}

func (r *tokenExchangeRequest) GetExchangeActorTokenIDOrToken() string {
	return r.exchangeActorTokenIDOrToken
}

func (r *tokenExchangeRequest) GetExchangeActorTokenClaims() map[string]any {
	return r.exchangeActorTokenClaims
}

func (r *tokenExchangeRequest) GetSubject() string {
	return r.subject
}

func (r *tokenExchangeRequest) SetCurrentScopes(scopes []string) {
	r.scopes = scopes
}

func (r *tokenExchangeRequest) SetRequestedTokenType(tt oidc.TokenType) {
	r.requestedTokenType = tt
}

func (r *tokenExchangeRequest) SetSubject(subject string) {
	r.subject = subject
}

// TokenExchange handles the OAuth 2.0 token exchange grant ("urn:ietf:params:oauth:grant-type:token-exchange")
func TokenExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	ctx, span := tracer.Start(r.Context(), "TokenExchange")
	defer span.End()
	r = r.WithContext(ctx)

	tokenExchangeReq, clientID, clientSecret, err := ParseTokenExchangeRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
	}

	tokenExchangeRequest, client, err := ValidateTokenExchangeRequest(r.Context(), tokenExchangeReq, clientID, clientSecret, exchanger)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	resp, err := CreateTokenExchangeResponse(r.Context(), tokenExchangeRequest, client, exchanger)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	httphelper.MarshalJSON(w, resp)
}

// ParseTokenExchangeRequest parses the http request into oidc.TokenExchangeRequest
func ParseTokenExchangeRequest(r *http.Request, decoder httphelper.Decoder) (_ *oidc.TokenExchangeRequest, clientID, clientSecret string, err error) {
	err = r.ParseForm()
	if err != nil {
		return nil, "", "", oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}

	request := new(oidc.TokenExchangeRequest)
	err = decoder.Decode(request, r.Form)
	if err != nil {
		return nil, "", "", oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}

	var ok bool
	if clientID, clientSecret, ok = r.BasicAuth(); ok {
		clientID, err = url.QueryUnescape(clientID)
		if err != nil {
			return nil, "", "", oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}

		clientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			return nil, "", "", oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
	}

	return request, clientID, clientSecret, nil
}

// ValidateTokenExchangeRequest validates the token exchange request parameters including authorization check of the client,
// subject_token and actor_token
func ValidateTokenExchangeRequest(
	ctx context.Context,
	oidcTokenExchangeRequest *oidc.TokenExchangeRequest,
	clientID, clientSecret string,
	exchanger Exchanger,
) (TokenExchangeRequest, Client, error) {
	ctx, span := tracer.Start(ctx, "ValidateTokenExchangeRequest")
	defer span.End()

	if oidcTokenExchangeRequest.SubjectToken == "" {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("subject_token missing")
	}

	if oidcTokenExchangeRequest.SubjectTokenType == "" {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("subject_token_type missing")
	}

	client, err := AuthorizeTokenExchangeClient(ctx, clientID, clientSecret, exchanger)
	if err != nil {
		return nil, nil, err
	}

	if oidcTokenExchangeRequest.RequestedTokenType != "" && !oidcTokenExchangeRequest.RequestedTokenType.IsSupported() {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("requested_token_type is not supported")
	}

	if !oidcTokenExchangeRequest.SubjectTokenType.IsSupported() {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("subject_token_type is not supported")
	}

	if oidcTokenExchangeRequest.ActorTokenType != "" && !oidcTokenExchangeRequest.ActorTokenType.IsSupported() {
		return nil, nil, oidc.ErrInvalidRequest().WithDescription("actor_token_type is not supported")
	}

	req, err := CreateTokenExchangeRequest(ctx, oidcTokenExchangeRequest, client, exchanger)
	if err != nil {
		return nil, nil, err
	}
	return req, client, nil
}

func CreateTokenExchangeRequest(
	ctx context.Context,
	oidcTokenExchangeRequest *oidc.TokenExchangeRequest,
	client Client,
	exchanger Exchanger,
) (TokenExchangeRequest, error) {
	ctx, span := tracer.Start(ctx, "CreateTokenExchangeRequest")
	defer span.End()

	teStorage, ok := exchanger.Storage().(TokenExchangeStorage)
	if !ok {
		return nil, unimplementedGrantError(oidc.GrantTypeTokenExchange)
	}

	exchangeSubjectTokenIDOrToken, exchangeSubject, exchangeSubjectTokenClaims, ok := GetTokenIDAndSubjectFromToken(ctx, exchanger,
		oidcTokenExchangeRequest.SubjectToken, oidcTokenExchangeRequest.SubjectTokenType, false)
	if !ok {
		return nil, oidc.ErrInvalidRequest().WithDescription("subject_token is invalid")
	}

	var (
		exchangeActorTokenIDOrToken, exchangeActor string
		exchangeActorTokenClaims                   map[string]any
	)
	if oidcTokenExchangeRequest.ActorToken != "" {
		exchangeActorTokenIDOrToken, exchangeActor, exchangeActorTokenClaims, ok = GetTokenIDAndSubjectFromToken(ctx, exchanger,
			oidcTokenExchangeRequest.ActorToken, oidcTokenExchangeRequest.ActorTokenType, true)
		if !ok {
			return nil, oidc.ErrInvalidRequest().WithDescription("actor_token is invalid")
		}
	}

	req := &tokenExchangeRequest{
		exchangeSubjectTokenIDOrToken: exchangeSubjectTokenIDOrToken,
		exchangeSubjectTokenType:      oidcTokenExchangeRequest.SubjectTokenType,
		exchangeSubject:               exchangeSubject,
		exchangeSubjectTokenClaims:    exchangeSubjectTokenClaims,

		exchangeActorTokenIDOrToken: exchangeActorTokenIDOrToken,
		exchangeActorTokenType:      oidcTokenExchangeRequest.ActorTokenType,
		exchangeActor:               exchangeActor,
		exchangeActorTokenClaims:    exchangeActorTokenClaims,

		subject:            exchangeSubject,
		resource:           oidcTokenExchangeRequest.Resource,
		audience:           oidcTokenExchangeRequest.Audience,
		scopes:             oidcTokenExchangeRequest.Scopes,
		requestedTokenType: oidcTokenExchangeRequest.RequestedTokenType,
		clientID:           client.GetID(),
		authTime:           time.Now(),
	}

	err := teStorage.ValidateTokenExchangeRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	err = teStorage.CreateTokenExchangeRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func GetTokenIDAndSubjectFromToken(
	ctx context.Context,
	exchanger Exchanger,
	token string,
	tokenType oidc.TokenType,
	isActor bool,
) (tokenIDOrToken, subject string, claims map[string]any, ok bool) {
	ctx, span := tracer.Start(ctx, "GetTokenIDAndSubjectFromToken")
	defer span.End()

	switch tokenType {
	case oidc.AccessTokenType:
		var accessTokenClaims *oidc.AccessTokenClaims
		tokenIDOrToken, subject, accessTokenClaims, ok = getTokenIDAndClaims(ctx, exchanger, token)
		if !ok {
			break
		}
		claims = accessTokenClaims.Claims
	case oidc.RefreshTokenType:
		refreshTokenRequest, err := exchanger.Storage().TokenRequestByRefreshToken(ctx, token)
		if err != nil {
			break
		}

		tokenIDOrToken, subject, ok = token, refreshTokenRequest.GetSubject(), true
	case oidc.IDTokenType:
		idTokenClaims, err := VerifyIDTokenHint[*oidc.IDTokenClaims](ctx, token, exchanger.IDTokenHintVerifier(ctx))
		if err != nil {
			break
		}

		tokenIDOrToken, subject, claims, ok = token, idTokenClaims.Subject, idTokenClaims.Claims, true
	}

	if !ok {
		if verifier, ok := exchanger.Storage().(TokenExchangeTokensVerifierStorage); ok {
			var err error
			if isActor {
				tokenIDOrToken, subject, claims, err = verifier.VerifyExchangeActorToken(ctx, token, tokenType)
			} else {
				tokenIDOrToken, subject, claims, err = verifier.VerifyExchangeSubjectToken(ctx, token, tokenType)
			}
			if err != nil {
				return "", "", nil, false
			}

			return tokenIDOrToken, subject, claims, true
		}

		return "", "", nil, false
	}

	return tokenIDOrToken, subject, claims, true
}

// AuthorizeTokenExchangeClient authorizes a client by validating the client_id and client_secret
func AuthorizeTokenExchangeClient(ctx context.Context, clientID, clientSecret string, exchanger Exchanger) (client Client, err error) {
	ctx, span := tracer.Start(ctx, "AuthorizeTokenExchangeClient")
	defer span.End()

	if err := AuthorizeClientIDSecret(ctx, clientID, clientSecret, exchanger.Storage()); err != nil {
		return nil, err
	}

	client, err = exchanger.Storage().GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithParent(err)
	}

	return client, nil
}

func CreateTokenExchangeResponse(
	ctx context.Context,
	tokenExchangeRequest TokenExchangeRequest,
	client Client,
	creator TokenCreator,
) (_ *oidc.TokenExchangeResponse, err error) {
	ctx, span := tracer.Start(ctx, "CreateTokenExchangeResponse")
	defer span.End()

	var (
		token, refreshToken, tokenType string
		validity                       time.Duration
	)

	switch tokenExchangeRequest.GetRequestedTokenType() {
	case oidc.AccessTokenType, oidc.RefreshTokenType:
		token, refreshToken, validity, err = CreateAccessToken(ctx, tokenExchangeRequest, client.AccessTokenType(), creator, client, "")
		if err != nil {
			return nil, err
		}

		tokenType = oidc.BearerToken
	case oidc.IDTokenType:
		token, err = CreateIDToken(ctx, IssuerFromContext(ctx), tokenExchangeRequest, client.IDTokenLifetime(), "", "", creator.Storage(), client)
		if err != nil {
			return nil, err
		}

		// not applicable (see https://datatracker.ietf.org/doc/html/rfc8693#section-2-2-1-2-6)
		tokenType = "N_A"
	default:
		// oidc.JWTTokenType and other custom token types are not supported for issuing.
		// In the future it can be considered to have custom tokens generation logic injected via op configuration
		// or via expanding Storage interface
		oidc.ErrInvalidRequest().WithDescription("requested_token_type is invalid")
	}

	exp := uint64(validity.Seconds())
	return &oidc.TokenExchangeResponse{
		AccessToken:     token,
		IssuedTokenType: tokenExchangeRequest.GetRequestedTokenType(),
		TokenType:       tokenType,
		ExpiresIn:       exp,
		RefreshToken:    refreshToken,
		Scopes:          tokenExchangeRequest.GetScopes(),
	}, nil
}

func getTokenIDAndClaims(ctx context.Context, userinfoProvider UserinfoProvider, accessToken string) (string, string, *oidc.AccessTokenClaims, bool) {
	tokenIDSubject, err := userinfoProvider.Crypto().Decrypt(accessToken)
	if err == nil {
		splitToken := strings.Split(tokenIDSubject, ":")
		if len(splitToken) != 2 {
			return "", "", nil, false
		}

		return splitToken[0], splitToken[1], nil, true
	}
	accessTokenClaims, err := VerifyAccessToken[*oidc.AccessTokenClaims](ctx, accessToken, userinfoProvider.AccessTokenVerifier(ctx))
	if err != nil {
		return "", "", nil, false
	}

	return accessTokenClaims.JWTID, accessTokenClaims.Subject, accessTokenClaims, true
}
