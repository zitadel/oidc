package op

import (
	"context"
	"errors"
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
		http.Error(w, err.Error(), http.StatusUnauthorized)
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
	return
}

func ParseTokenRevocationRequest(r *http.Request, revoker Revoker) (token, tokenTypeHint, clientID string, err error) {
	err = r.ParseForm()
	if err != nil {
		return "", "", "", errors.New("unable to parse request")
	}
	req := new(struct {
		oidc.RevocationRequest
		oidc.ClientAssertionParams
	})
	err = revoker.Decoder().Decode(req, r.Form)
	if err != nil {
		return "", "", "", errors.New("unable to parse request")
	}
	if revokerJWTProfile, ok := revoker.(RevokerJWTProfile); ok && req.ClientAssertion != "" {
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
			return "", "", "", errors.New("invalid basic auth header")
		}
		clientSecret, err = url.QueryUnescape(clientSecret)
		if err != nil {
			return "", "", "", errors.New("invalid basic auth header")
		}
		if err := revoker.Storage().AuthorizeClientIDSecret(r.Context(), clientID, clientSecret); err != nil {
			return "", "", "", err
		}
		return req.Token, req.TokenTypeHint, clientID, nil
	}
	return "", "", "", errors.New("invalid authorization")
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
