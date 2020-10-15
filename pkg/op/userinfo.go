package op

import (
	"errors"
	"net/http"
	"strings"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type UserinfoProvider interface {
	Decoder() utils.Decoder
	Crypto() Crypto
	Storage() Storage
	AccessTokenVerifier() AccessTokenVerifier
}

func userinfoHandler(userinfoProvider UserinfoProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Userinfo(w, r, userinfoProvider)
	}
}

func Userinfo(w http.ResponseWriter, r *http.Request, userinfoProvider UserinfoProvider) {
	accessToken, err := getAccessToken(r, userinfoProvider.Decoder())
	if err != nil {
		http.Error(w, "access token missing", http.StatusUnauthorized)
		return
	}
	tokenIDSubject, err := userinfoProvider.Crypto().Decrypt(accessToken)
	if err != nil {
		accessTokenClaims, err := VerifyAccessToken(r.Context(), accessToken, userinfoProvider.AccessTokenVerifier())
		if err != nil {
			http.Error(w, "access token invalid", http.StatusUnauthorized)
			return
		}
		tokenID = accessTokenClaims.GetTokenID()
	}
	splittedToken := strings.Split(tokenIDSubject, ":")
	info, err := userinfoProvider.Storage().GetUserinfoFromToken(r.Context(), splittedToken[0], splittedToken[1], r.Header.Get("origin"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		utils.MarshalJSON(w, err)
		return
	}
	utils.MarshalJSON(w, info)
}

func getAccessToken(r *http.Request, decoder utils.Decoder) (string, error) {
	authHeader := r.Header.Get("authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, "Bearer ")
		if len(parts) != 2 {
			return "", errors.New("invalid auth header")
		}
		return parts[1], nil
	}
	err := r.ParseForm()
	if err != nil {
		return "", errors.New("unable to parse request")
	}
	req := new(oidc.UserInfoRequest)
	err = decoder.Decode(req, r.Form)
	if err != nil {
		return "", errors.New("unable to parse request")
	}
	return req.AccessToken, nil
}
