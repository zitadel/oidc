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
	tokenID, err := userinfoProvider.Crypto().Decrypt(accessToken)
	if err != nil {
		http.Error(w, "access token missing", http.StatusUnauthorized)
		return
	}
	info, err := userinfoProvider.Storage().GetUserinfoFromToken(r.Context(), tokenID, r.Header.Get("origin"))
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
