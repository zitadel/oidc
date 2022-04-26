package op

import (
	"context"
	"errors"
	"net/http"
	"strings"

	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

type UserinfoProvider interface {
	Decoder() httphelper.Decoder
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
	accessToken, err := ParseUserinfoRequest(r, userinfoProvider.Decoder())
	if err != nil {
		http.Error(w, "access token missing", http.StatusUnauthorized)
		return
	}
	tokenID, subject, ok := getTokenIDAndSubject(r.Context(), userinfoProvider, accessToken)
	if !ok {
		http.Error(w, "access token invalid", http.StatusUnauthorized)
		return
	}
	info := oidc.NewUserInfo()
	err = userinfoProvider.Storage().SetUserinfoFromToken(r.Context(), info, tokenID, subject, r.Header.Get("origin"))
	if err != nil {
		httphelper.MarshalJSONWithStatus(w, err, http.StatusForbidden)
		return
	}
	httphelper.MarshalJSON(w, info)
}

func ParseUserinfoRequest(r *http.Request, decoder httphelper.Decoder) (string, error) {
	accessToken, err := getAccessToken(r)
	if err == nil {
		return accessToken, nil
	}
	err = r.ParseForm()
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

func getAccessToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("authorization")
	if authHeader == "" {
		return "", errors.New("no auth header")
	}
	parts := strings.Split(authHeader, "Bearer ")
	if len(parts) != 2 {
		return "", errors.New("invalid auth header")
	}
	return parts[1], nil
}

func getTokenIDAndSubject(ctx context.Context, userinfoProvider UserinfoProvider, accessToken string) (string, string, bool) {
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
