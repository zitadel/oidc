package op

import (
	"context"
	"errors"
	"net/http"
	"strings"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type UserinfoProvider interface {
	Decoder() httphelper.Decoder
	Crypto() Crypto
	Storage() Storage
	AccessTokenVerifier(context.Context) *AccessTokenVerifier
}

func userinfoHandler(userinfoProvider UserinfoProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Userinfo(w, r, userinfoProvider)
	}
}

func Userinfo(w http.ResponseWriter, r *http.Request, userinfoProvider UserinfoProvider) {
	ctx, span := tracer.Start(r.Context(), "Userinfo")
	r = r.WithContext(ctx)
	defer span.End()

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
	info := new(oidc.UserInfo)
	err = userinfoProvider.Storage().SetUserinfoFromToken(r.Context(), info, tokenID, subject, r.Header.Get("origin"))
	if err != nil {
		httphelper.MarshalJSONWithStatus(w, err, http.StatusForbidden)
		return
	}
	httphelper.MarshalJSON(w, info)
}

func ParseUserinfoRequest(r *http.Request, decoder httphelper.Decoder) (string, error) {
	ctx, span := tracer.Start(r.Context(), "ParseUserinfoRequest")
	r = r.WithContext(ctx)
	defer span.End()

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
	ctx, span := tracer.Start(r.Context(), "getAccessToken")
	r = r.WithContext(ctx)
	defer span.End()

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
	ctx, span := tracer.Start(ctx, "getTokenIDAndSubject")
	defer span.End()

	tokenIDSubject, err := userinfoProvider.Crypto().Decrypt(accessToken)
	if err == nil {
		splitToken := strings.Split(tokenIDSubject, ":")
		if len(splitToken) != 2 {
			return "", "", false
		}
		return splitToken[0], splitToken[1], true
	}
	accessTokenClaims, err := VerifyAccessToken[*oidc.AccessTokenClaims](ctx, accessToken, userinfoProvider.AccessTokenVerifier(ctx))
	if err != nil {
		return "", "", false
	}
	return accessTokenClaims.JWTID, accessTokenClaims.Subject, true
}
