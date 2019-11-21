package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/rp"
	"github.com/caos/oidc/pkg/utils"
	"github.com/caos/utils/logging"
)

var (
	callbackPath string = "/auth/callback"
	hashKey      []byte = []byte("test")
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	issuer := os.Getenv("ISSUER")
	port := os.Getenv("PORT")

	ctx := context.Background()

	rpConfig := &rp.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
		CallbackURL:  fmt.Sprintf("http://localhost:%v%v", port, callbackPath),
		Scopes:       []string{"openid", "profile", "email"},
	}
	cookieHandler := utils.NewCookieHandler(hashKey, nil, utils.WithUnsecure())
	provider, err := rp.NewDefaultRP(rpConfig, rp.WithCookieHandler(cookieHandler))
	logging.Log("APP-nx6PeF").OnError(err).Panic("error creating provider")

	// state := "foobar"
	state := uuid.New().String()

	http.Handle("/login", provider.AuthURLHandler(state))
	// http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
	// 	http.Redirect(w, r, provider.AuthURL(state), http.StatusFound)
	// })

	// http.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
	// 	tokens, err := provider.CodeExchange(ctx, r.URL.Query().Get("code"))
	// 	if err != nil {
	// 		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusUnauthorized)
	// 		return
	// 	}
	// 	data, err := json.Marshal(tokens)
	// 	if err != nil {
	// 		http.Error(w, err.Error(), http.StatusInternalServerError)
	// 		return
	// 	}
	// 	w.Write(data)
	// })

	var marshal = func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string) {
		_ = state
		data, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}

	http.Handle(callbackPath, provider.CodeExchangeHandler(marshal))

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		tokens, err := provider.ClientCredentials(ctx, "urn:abraxas:iam:audience_client_id:TM-V3")
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
	logging.Log("APP-upQxIG").Infof("listening on http://%s/", lis)
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
