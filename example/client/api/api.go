package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	publicURL         string = "/public"
	protectedURL      string = "/protected"
	protectedClaimURL string = "/protected/{claim}/{value}"
)

func main() {
	keyPath := os.Getenv("KEY")
	port := os.Getenv("PORT")
	issuer := os.Getenv("ISSUER")

	provider, err := rs.NewResourceServerFromKeyFile(context.TODO(), issuer, keyPath)
	if err != nil {
		slog.Error("error creating provider", "error", err)
		os.Exit(1)
	}

	router := chi.NewRouter()

	// public url accessible without any authorization
	// will print `OK` and current timestamp
	router.HandleFunc(publicURL, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK " + time.Now().String()))
	})

	// protected url which needs an active token
	// will print the result of the introspection endpoint on success
	router.HandleFunc(protectedURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := rs.Introspect[*oidc.IntrospectionResponse](r.Context(), provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	// protected url which needs an active token and checks if the response of the introspect endpoint
	// contains a requested claim with the required (string) value
	// e.g. /protected/username/livio@zitadel.example
	router.HandleFunc(protectedClaimURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := rs.Introspect[*oidc.IntrospectionResponse](r.Context(), provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		requestedClaim := chi.URLParam(r, "claim")
		requestedValue := chi.URLParam(r, "value")

		value, ok := resp.Claims[requestedClaim].(string)
		if !ok || value == "" || value != requestedValue {
			http.Error(w, "claim does not match", http.StatusForbidden)
			return
		}
		w.Write([]byte("authorized with value " + value))
	})

	lis := fmt.Sprintf("127.0.0.1:%s", port)
	slog.Info("listening", "url", "http://"+lis+"/")
	if err := http.ListenAndServe(lis, router); err != nil {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}

func checkToken(w http.ResponseWriter, r *http.Request) (bool, string) {
	auth := r.Header.Get("authorization")
	if auth == "" {
		http.Error(w, "auth header missing", http.StatusUnauthorized)
		return false, ""
	}
	if !strings.HasPrefix(auth, oidc.PrefixBearer) {
		http.Error(w, "invalid header", http.StatusUnauthorized)
		return false, ""
	}
	return true, strings.TrimPrefix(auth, oidc.PrefixBearer)
}
