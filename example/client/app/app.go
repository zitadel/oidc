package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

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

	redirectURI := fmt.Sprintf("http://localhost:%v%v", port, callbackPath)
	scopes := []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeAddress, "hodor"}
	cookieHandler := utils.NewCookieHandler(key, key, utils.WithUnsecure())
	provider, err := rp.NewRelayingPartyOIDC(issuer, clientID, clientSecret, redirectURI, scopes,
		rp.WithPKCE(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5*time.Second)),
	)
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

	http.HandleFunc("/jwt-profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			tpl := `
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Login</title>
		</head>
		<body>
			<form method="POST" action="/jwt-profile" enctype="multipart/form-data">
				<label for="key">Select a key file:</label>
				<input type="file" id="key" name="key">
				<button type="submit">Upload</button>
			</form>
		</body>
	</html>`
			t, err := template.New("login").Parse(tpl)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			err = t.Execute(w, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		} else {
			err := r.ParseMultipartForm(4 << 10)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			file, handler, err := r.FormFile("key")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer file.Close()

			key, err := ioutil.ReadAll(file)
			fmt.Println(handler.Header)
			assertion, err := oidc.NewJWTProfileAssertionFromFileData(key, []string{issuer})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			token, err := rp.JWTProfileExchange(ctx, assertion, provider)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			data, err := json.Marshal(token)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(data)
		}
	})
	lis := fmt.Sprintf("127.0.0.1:%s", port)
	logrus.Infof("listening on http://%s/", lis)
	logrus.Fatal(http.ListenAndServe("127.0.0.1:"+port, nil))
}
