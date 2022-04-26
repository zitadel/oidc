package op

import (
	"context"
	"net/http"
	"time"

	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

type JWTAuthorizationGrantExchanger interface {
	Exchanger
	JWTProfileVerifier() JWTProfileVerifier
}

//JWTProfile handles the OAuth 2.0 JWT Profile Authorization Grant https://tools.ietf.org/html/rfc7523#section-2.1
func JWTProfile(w http.ResponseWriter, r *http.Request, exchanger JWTAuthorizationGrantExchanger) {
	profileRequest, err := ParseJWTProfileGrantRequest(r, exchanger.Decoder())
	if err != nil {
		RequestError(w, r, err)
	}

	tokenRequest, err := VerifyJWTAssertion(r.Context(), profileRequest.Assertion, exchanger.JWTProfileVerifier())
	if err != nil {
		RequestError(w, r, err)
		return
	}

	tokenRequest.Scopes, err = exchanger.Storage().ValidateJWTProfileScopes(r.Context(), tokenRequest.Issuer, profileRequest.Scope)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	resp, err := CreateJWTTokenResponse(r.Context(), tokenRequest, exchanger)
	if err != nil {
		RequestError(w, r, err)
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

//CreateJWTTokenResponse creates
func CreateJWTTokenResponse(ctx context.Context, tokenRequest TokenRequest, creator TokenCreator) (*oidc.AccessTokenResponse, error) {
	id, exp, err := creator.Storage().CreateAccessToken(ctx, tokenRequest)
	if err != nil {
		return nil, err
	}
	accessToken, err := CreateBearerToken(id, tokenRequest.GetSubject(), creator.Crypto())
	if err != nil {
		return nil, err
	}

	return &oidc.AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   oidc.BearerToken,
		ExpiresIn:   uint64(exp.Sub(time.Now().UTC()).Seconds()),
	}, nil
}

//ParseJWTProfileRequest has been renamed to ParseJWTProfileGrantRequest
//
//deprecated: use ParseJWTProfileGrantRequest
func ParseJWTProfileRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.JWTProfileGrantRequest, error) {
	return ParseJWTProfileGrantRequest(r, decoder)
}
