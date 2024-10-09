package op

import (
	"context"
	"net/http"
	"time"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type JWTAuthorizationGrantExchanger interface {
	Exchanger
	JWTProfileVerifier(context.Context) *JWTProfileVerifier
}

// JWTProfile handles the OAuth 2.0 JWT Profile Authorization Grant https://tools.ietf.org/html/rfc7523#section-2.1
func JWTProfile(w http.ResponseWriter, r *http.Request, exchanger JWTAuthorizationGrantExchanger) {
	ctx, span := tracer.Start(r.Context(), "JWTProfile")
	defer span.End()
	r = r.WithContext(ctx)

	profileRequest, err := ParseJWTProfileGrantRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
	}

	tokenRequest, err := VerifyJWTAssertion(r.Context(), profileRequest.Assertion, exchanger.JWTProfileVerifier(r.Context()))
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}

	tokenRequest.Scopes, err = exchanger.Storage().ValidateJWTProfileScopes(r.Context(), tokenRequest.Issuer, profileRequest.Scope)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	resp, err := CreateJWTTokenResponse(r.Context(), tokenRequest, exchanger)
	if err != nil {
		RequestError(w, r, err, exchanger.Logger())
		return
	}
	httphelper.MarshalJSON(w, resp)
}

func ParseJWTProfileGrantRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.JWTProfileGrantRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	tokenReq := new(oidc.JWTProfileGrantRequest)
	err = decoder.Decode(tokenReq, r.Form)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	return tokenReq, nil
}

// CreateJWTTokenResponse creates an access_token response for a JWT Profile Grant request
// by default the access_token is an opaque string, but can be specified by implementing the JWTProfileTokenStorage interface
func CreateJWTTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator) (*oidc.AccessTokenResponse, error) {
	ctx, span := tracer.Start(ctx, "CreateJWTTokenResponse")
	defer span.End()

	// return an opaque token as default to not break current implementations
	tokenType := AccessTokenTypeBearer

	// the current CreateAccessToken function, esp. CreateJWT requires an implementation of an AccessTokenClient
	client := &jwtProfileClient{
		id: tokenRequest.GetSubject(),
	}

	// by implementing the JWTProfileTokenStorage the storage can specify the AccessTokenType to be returned
	tokenStorage, ok := creator.Storage().(JWTProfileTokenStorage)
	if ok {
		var err error
		tokenType, err = tokenStorage.JWTProfileTokenType(ctx, tokenRequest)
		if err != nil {
			return nil, err
		}
	}

	accessToken, _, validity, err := CreateAccessToken(ctx, tokenRequest, tokenType, creator, client, "")
	if err != nil {
		return nil, err
	}
	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(validity.Seconds()),
		Scope:       tokenRequest.GetScopes(),
	}, nil
}

// ParseJWTProfileRequest has been renamed to ParseJWTProfileGrantRequest
//
// deprecated: use ParseJWTProfileGrantRequest
func ParseJWTProfileRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.JWTProfileGrantRequest, error) {
	return ParseJWTProfileGrantRequest(r, decoder)
}

type jwtProfileClient struct {
	id string
}

func (j *jwtProfileClient) GetID() string {
	return j.id
}

func (j *jwtProfileClient) ClockSkew() time.Duration {
	return 0
}

func (j *jwtProfileClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string {
		return scopes
	}
}

func (j *jwtProfileClient) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{
		oidc.GrantTypeBearer,
	}
}
