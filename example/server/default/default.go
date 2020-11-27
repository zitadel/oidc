package main

import (
	"context"
	"crypto/sha256"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/caos/oidc/example/internal/mock"
	"github.com/caos/oidc/pkg/op"
)

func main() {
	ctx := context.Background()
	port := "9998"
	config := &op.Config{
		Issuer:    "http://localhost:9998/",
		CryptoKey: sha256.Sum256([]byte("test")),
	}
	storage := mock.NewAuthStorage()
	handler, err := op.NewOpenIDProvider(ctx, config, storage, op.WithCustomTokenEndpoint(op.NewEndpoint("test")))
	if err != nil {
		log.Fatal(err)
	}
	router := handler.HttpHandler().(*mux.Router)
	router.Methods("GET").Path("/login").HandlerFunc(HandleLogin)
	router.Methods("POST").Path("/login").HandlerFunc(HandleCallback)
	server := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
	<-ctx.Done()
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	tpl := `
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Login</title>
		</head>
		<body>
			<form method="POST" action="/login">
				<input name="client"/>
				<button type="submit">Login</button>
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
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	client := r.FormValue("client")
	http.Redirect(w, r, "/authorize/callback?id="+client, http.StatusFound)
}
