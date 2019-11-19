package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/caos/go-oidc/pkg/oidc"
	"github.com/caos/go-oidc/pkg/oidc/defaults"
	"github.com/caos/utils/logging"
)

const (
	publicURL            string = "/public"
	protectedURL         string = "/protected"
	protectedExchangeURL string = "/protected/exchange"
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	issuer := os.Getenv("ISSUER")
	port := os.Getenv("PORT")

	// ctx := context.Background()

	providerConfig := &oidc.ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
	}
	provider, err := defaults.NewDefaultProvider(providerConfig)
	logging.Log("APP-nx6PeF").OnError(err).Panic("error creating provider")

	http.HandleFunc(publicURL, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	http.HandleFunc(protectedURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		resp, err := provider.Introspect(r.Context(), token)
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

	http.HandleFunc(protectedExchangeURL, func(w http.ResponseWriter, r *http.Request) {
		ok, token := checkToken(w, r)
		if !ok {
			return
		}
		tokens, err := provider.DelegationTokenExchange(r.Context(), token, oidc.WithResource([]string{"Test"}))
		if err != nil {
			http.Error(w, "failed to exchange token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		data, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	lis := fmt.Sprintf("127.0.0.1:%s", port)
	log.Printf("listening on http://%s/", lis)
	log.Fatal(http.ListenAndServe(lis, nil))
}

func checkToken(w http.ResponseWriter, r *http.Request) (bool, string) {
	token := r.Header.Get("authorization")
	if token == "" {
		http.Error(w, "Auth header missing", http.StatusUnauthorized)
		return false, ""
	}
	return true, token
}
