package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	queryAuthRequestID = "authRequestID"
)

var (
	loginTmpl, _ = template.New("login").Parse(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>Login</title>
		</head>
		<body style="display: flex; align-items: center; justify-content: center; height: 100vh;">
			<form method="POST" action="/login/username" style="height: 200px; width: 200px;">
				<input type="hidden" name="id" value="{{.ID}}">
				<div>
					<label for="username">Username:</label>
					<input id="username" name="username" style="width: 100%">
				</div>
				<div>
					<label for="password">Password:</label>
					<input id="password" name="password" style="width: 100%">
				</div>
				<p style="color:red; min-height: 1rem;">{{.Error}}</p>
				<button type="submit">Login</button>
			</form>
		</body>
	</html>`)
)

type login struct {
	authenticate authenticate
	router       chi.Router
	callback     func(context.Context, string) string
}

func NewLogin(authenticate authenticate, callback func(context.Context, string) string, issuerInterceptor *op.IssuerInterceptor) *login {
	l := &login{
		authenticate: authenticate,
		callback:     callback,
	}
	l.createRouter(issuerInterceptor)
	return l
}

func (l *login) createRouter(issuerInterceptor *op.IssuerInterceptor) {
	l.router = chi.NewRouter()
	l.router.Get("/username", l.loginHandler)
	l.router.With(issuerInterceptor.Handler).Post("/username", l.checkLoginHandler)
}

type authenticate interface {
	CheckUsernamePassword(ctx context.Context, username, password, id string) error
}

func (l *login) loginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
		return
	}
	//the oidc package will pass the id of the auth request as query parameter
	//we will use this id through the login process and therefore pass it to the  login page
	renderLogin(w, r.FormValue(queryAuthRequestID), nil)
}

func renderLogin(w http.ResponseWriter, id string, err error) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	data := &struct {
		ID    string
		Error string
	}{
		ID:    id,
		Error: errMsg,
	}
	err = loginTmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (l *login) checkLoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	id := r.FormValue("id")
	err = l.authenticate.CheckUsernamePassword(r.Context(), username, password, id)
	if err != nil {
		renderLogin(w, id, err)
		return
	}
	http.Redirect(w, r, l.callback(r.Context(), id), http.StatusFound)
}
