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
	config := &op.Config{
		Issuer:    "http://localhost:9998/",
		CryptoKey: sha256.Sum256([]byte("test")),
		Port:      "9998",
	}
	storage := mock.NewAuthStorage()
	handler, err := op.NewDefaultOP(ctx, config, storage, op.WithCustomTokenEndpoint("test"))
	if err != nil {
		log.Fatal(err)
	}
	router := handler.HttpHandler().Handler.(*mux.Router)
	router.Methods("GET").Path("/login").HandlerFunc(HandleLogin)
	router.Methods("POST").Path("/login").HandlerFunc(HandleCallback)
	op.Start(ctx, handler)
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
	http.Redirect(w, r, "/authorize/"+client, http.StatusFound)
}
