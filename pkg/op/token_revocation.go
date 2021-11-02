package op

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	httphelper "github.com/caos/oidc/pkg/http"
	"github.com/caos/oidc/pkg/oidc"
)

type Revoker interface {
	Decoder() httphelper.Decoder
	Crypto() Crypto
	Storage() Storage
	AccessTokenVerifier() AccessTokenVerifier
	AuthMethodPrivateKeyJWTSupported() bool
	AuthMethodPostSupported() bool
}

type RevokerJWTProfile interface {
	Revoker
	JWTProfileVerifier() JWTProfileVerifier
}

func revocationHandler(revoker Revoker) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Revoke(w, r, revoker)
	}
}

func Revoke(w http.ResponseWriter, r *http.Request, revoker Revoker) {
	token, _, clientID, err := ParseTokenRevocationRequest(r, revoker)
	if err != nil {
		RevocationRequestError(w, r, err)
		return
	}
	tokenID, subject, ok := getTokenIDAndSubjectForRevocation(r.Context(), revoker, token)
	if ok {
		token = tokenID
	}
	if err := revoker.Storage().RevokeToken(r.Context(), token, subject, clientID); err != nil {
		RevocationRequestError(w, r, err)
		return
	}
	httphelper.MarshalJSON(w, nil)
}

func ParseTokenRevocationRequest(r *http.Request, revoker Revoker) (token, tokenTypeHint, clientID string, err error) {
	err = r.ParseForm()
	if err != nil {
		return "", "", "", oidc.ErrInvalidRequest().WithDescription("unable to parse request").WithParent(err)
	}
	req := new(struct {
		oidc.RevocationRequest
		oidc.ClientAssertionParams        //for auth_method private_key_jwt
		ClientID                   string `schema:"client_id"`     //for auth_method none and post
		ClientSecret               string `schema:"client_secret"` //for auth_method post
	})
	err = revoker.Decoder().Decode(req, r.Form)
	if err != nil {
		return "", "", "", oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	if req.ClientAssertionType == oidc.ClientAssertionTypeJWTAssertion {
		revokerJWTProfile, ok := revoker.(RevokerJWTProfile)
		if !ok || !revoker.AuthMethodPrivateKeyJWTSupported() {
			return "", "", "", oidc.ErrInvalidClient().WithDescription("auth_method private_key_jwt not supported")
		}
		profile, err := VerifyJWTAssertion(r.Context(), req.ClientAssertion, revokerJWTProfile.JWTProfileVerifier())
		if err == nil {
			return req.Token, req.TokenTypeHint, profile.Issuer, nil
		}
		return "", "", "", err
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		clientID, err = url.QueryUnescape(clientID)
		if err != nil {
			return "", "", "", oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
		clientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			return "", "", "", oidc.ErrInvalidClient().WithDescription("invalid basic auth header").WithParent(err)
		}
		if err = AuthorizeClientIDSecret(r.Context(), clientID, clientSecret, revoker.Storage()); err != nil {
			return "", "", "", err
		}
		return req.Token, req.TokenTypeHint, clientID, nil
	}
	if req.ClientID == "" {
		return "", "", "", oidc.ErrInvalidClient().WithDescription("invalid authorization")
	}
	client, err := revoker.Storage().GetClientByClientID(r.Context(), req.ClientID)
	if err != nil {
		return "", "", "", oidc.ErrInvalidClient().WithParent(err)
	}
	if req.ClientSecret == "" {
		if client.AuthMethod() != oidc.AuthMethodNone {
			return "", "", "", oidc.ErrInvalidClient().WithDescription("invalid authorization")
		}
		return req.Token, req.TokenTypeHint, req.ClientID, nil
	}
	if client.AuthMethod() == oidc.AuthMethodPost && !revoker.AuthMethodPostSupported() {
		return "", "", "", oidc.ErrInvalidClient().WithDescription("auth_method post not supported")
	}
	if err = AuthorizeClientIDSecret(r.Context(), req.ClientID, req.ClientSecret, revoker.Storage()); err != nil {
		return "", "", "", err
	}
	return req.Token, req.TokenTypeHint, req.ClientID, nil
}

func RevocationRequestError(w http.ResponseWriter, r *http.Request, err error) {
	e := oidc.DefaultToServerError(err, err.Error())
	status := http.StatusBadRequest
	if e.ErrorType == oidc.InvalidClient {
		status = 401
	}
	httphelper.MarshalJSONWithStatus(w, e, status)
}

func getTokenIDAndSubjectForRevocation(ctx context.Context, userinfoProvider UserinfoProvider, accessToken string) (string, string, bool) {
	tokenIDSubject, err := userinfoProvider.Crypto().Decrypt(accessToken)
	if err == nil {
		splitToken := strings.Split(tokenIDSubject, ":")
		if len(splitToken) != 2 {
			return "", "", false
		}
		return splitToken[0], splitToken[1], true
	}
	accessTokenClaims, err := VerifyAccessToken(ctx, accessToken, userinfoProvider.AccessTokenVerifier())
	if err != nil {
		return "", "", false
	}
	return accessTokenClaims.GetTokenID(), accessTokenClaims.GetSubject(), true
}
