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

// UserinfoMTLSProvider is an optional interface for providers that support
// certificate-bound access token verification at the UserInfo endpoint (RFC 8705).
type UserinfoMTLSProvider interface {
	UserinfoProvider
	MTLSConfig() *MTLSConfig
}

func userinfoHandler(userinfoProvider UserinfoProvider) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Userinfo(w, r, userinfoProvider)
	}
}

func Userinfo(w http.ResponseWriter, r *http.Request, userinfoProvider UserinfoProvider) {
	ctx, span := Tracer.Start(r.Context(), "Userinfo")
	r = r.WithContext(ctx)
	defer span.End()

	accessToken, err := ParseUserinfoRequest(r, userinfoProvider.Decoder())
	if err != nil {
		http.Error(w, "access token missing", http.StatusUnauthorized)
		return
	}
	tokenID, subject, claims, ok := getTokenIDAndSubjectAndClaims(r.Context(), userinfoProvider, accessToken)
	if !ok {
		http.Error(w, "access token invalid", http.StatusUnauthorized)
		return
	}

	// Verify certificate-bound token if cnf claim is present (RFC 8705)
	if cnfThumbprint := GetCnfThumbprintFromClaims(claims); cnfThumbprint != "" {
		mtlsProvider, ok := userinfoProvider.(UserinfoMTLSProvider)
		if !ok {
			http.Error(w, "certificate-bound token not supported", http.StatusUnauthorized)
			return
		}
		if err := VerifyCertificateBindingFromRequest(r, mtlsProvider.MTLSConfig(), cnfThumbprint); err != nil {
			http.Error(w, "certificate binding verification failed", http.StatusUnauthorized)
			return
		}
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
	ctx, span := Tracer.Start(r.Context(), "ParseUserinfoRequest")
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
	ctx, span := Tracer.Start(r.Context(), "getAccessToken")
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
	tokenID, subject, _, ok := getTokenIDAndSubjectAndClaims(ctx, userinfoProvider, accessToken)
	return tokenID, subject, ok
}

// getTokenIDAndSubjectAndClaims returns token ID, subject, and claims (for JWT tokens).
// For opaque tokens, claims will be nil.
func getTokenIDAndSubjectAndClaims(ctx context.Context, userinfoProvider UserinfoProvider, accessToken string) (string, string, map[string]any, bool) {
	ctx, span := Tracer.Start(ctx, "getTokenIDAndSubjectAndClaims")
	defer span.End()

	tokenIDSubject, err := userinfoProvider.Crypto().Decrypt(accessToken)
	if err == nil {
		splitToken := strings.Split(tokenIDSubject, ":")
		if len(splitToken) != 2 {
			return "", "", nil, false
		}
		// Opaque token - no claims available directly
		return splitToken[0], splitToken[1], nil, true
	}
	accessTokenClaims, err := VerifyAccessToken[*oidc.AccessTokenClaims](ctx, accessToken, userinfoProvider.AccessTokenVerifier(ctx))
	if err != nil {
		return "", "", nil, false
	}
	return accessTokenClaims.JWTID, accessTokenClaims.Subject, accessTokenClaims.Claims, true
}
