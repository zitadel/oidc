package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/zitadel/oidc/v2/pkg/client/rs"
	"github.com/zitadel/oidc/v2/pkg/oidc"
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

	provider, err := rs.NewResourceServerFromKeyFile(issuer, keyPath)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	router := mux.NewRouter()

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
		resp, err := rs.Introspect(r.Context(), provider, token)
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
		resp, err := rs.Introspect(r.Context(), provider, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		params := mux.Vars(r)
		requestedClaim := params["claim"]
		requestedValue := params["value"]
		value, ok := resp.Claims[requestedClaim].(string)
		if !ok || value == "" || value != requestedValue {
			http.Error(w, "claim does not match", http.StatusForbidden)
			return
		}
		w.Write([]byte("authorized with value " + value))
	})

	lis := fmt.Sprintf("127.0.0.1:%s", port)
	log.Printf("listening on http://%s/", lis)
	log.Fatal(http.ListenAndServe(lis, router))
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
