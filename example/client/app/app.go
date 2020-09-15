package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/rp"
	"github.com/caos/oidc/pkg/utils"
)

var (
	callbackPath string = "/auth/callback"
	key          []byte = []byte("test1234test1234")
)

func main() {
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	issuer := os.Getenv("ISSUER")
	port := os.Getenv("PORT")

	ctx := context.Background()

	rpConfig := &rp.Configuration{
		Issuer: issuer,
		Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  fmt.Sprintf("http://localhost:%v%v", port, callbackPath),
			Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
		},
	}
	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	provider, err := rp.NewRelayingParty(rpConfig, rp.WithCookieHandler(cookieHandler), rp.WithPKCE(cookieHandler), rp.WithVerifierOpts(rp.WithIssuedAtOffset(-3*time.Minute))) //,
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	//generate some state (representing the state of the user in your application,
	//e.g. the page where he was before sending him to login
	state := func() string {
		return uuid.New().String()
	}

	//register the AuthURLHandler at your preferred path
	//the AuthURLHandler creates the auth request and redirects the user to the auth server
	//including state handling with secure cookie and the possibility to use PKCE
	http.Handle("/login", rp.AuthURLHandler(state, provider))

	//for demonstration purposes the returned tokens (access token, id_token an its parsed claims)
	//are written as JSON objects onto response
	marshal := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens, state string) {
		_ = state
		data, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}

	//register the CodeExchangeHandler at the callbackPath
	//the CodeExchangeHandler handles the auth response, creates the token request and calls the callback function
	//with the returned tokens from the token endpoint
	http.Handle(callbackPath, rp.CodeExchangeHandler(marshal, provider))

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		tokens, err := rp.ClientCredentials(ctx, provider, "scope")
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
	logrus.Infof("listening on http://%s/", lis)
	logrus.Fatal(http.ListenAndServe("127.0.0.1:"+port, nil))
}
