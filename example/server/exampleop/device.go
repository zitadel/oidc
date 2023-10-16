package exampleop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/securecookie"
	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type deviceAuthenticate interface {
	CheckUsernamePasswordSimple(username, password string) error
	op.DeviceAuthorizationStorage

	// GetDeviceAuthorizationByUserCode resturns the current state of the device authorization flow,
	// identified by the user code.
	GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error)

	// CompleteDeviceAuthorization marks a device authorization entry as Completed,
	// identified by userCode. The Subject is added to the state, so that
	// GetDeviceAuthorizatonState can use it to create a new Access Token.
	CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error

	// DenyDeviceAuthorization marks a device authorization entry as Denied.
	DenyDeviceAuthorization(ctx context.Context, userCode string) error
}

type deviceLogin struct {
	storage deviceAuthenticate
	cookie  *securecookie.SecureCookie
}

func registerDeviceAuth(storage deviceAuthenticate, router chi.Router) {
	l := &deviceLogin{
		storage: storage,
		cookie:  securecookie.New(securecookie.GenerateRandomKey(32), nil),
	}

	router.HandleFunc("/", l.userCodeHandler)
	router.Post("/login", l.loginHandler)
	router.HandleFunc("/confirm", l.confirmHandler)
}

func renderUserCode(w io.Writer, err error) {
	data := struct {
		Error string
	}{
		Error: errMsg(err),
	}

	if err := templates.ExecuteTemplate(w, "usercode", data); err != nil {
		logrus.Error(err)
	}
}

func renderDeviceLogin(w http.ResponseWriter, userCode string, err error) {
	data := &struct {
		UserCode string
		Error    string
	}{
		UserCode: userCode,
		Error:    errMsg(err),
	}
	if err = templates.ExecuteTemplate(w, "device_login", data); err != nil {
		logrus.Error(err)
	}
}

func renderConfirmPage(w http.ResponseWriter, username, clientID string, scopes []string) {
	data := &struct {
		Username string
		ClientID string
		Scopes   []string
	}{
		Username: username,
		ClientID: clientID,
		Scopes:   scopes,
	}
	if err := templates.ExecuteTemplate(w, "confirm_device", data); err != nil {
		logrus.Error(err)
	}
}

func (d *deviceLogin) userCodeHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		renderUserCode(w, err)
		return
	}
	userCode := r.Form.Get("user_code")
	if userCode == "" {
		if prompt, _ := url.QueryUnescape(r.Form.Get("prompt")); prompt != "" {
			err = errors.New(prompt)
		}
		renderUserCode(w, err)
		return
	}

	renderDeviceLogin(w, userCode, nil)
}

func redirectBack(w http.ResponseWriter, r *http.Request, prompt string) {
	values := make(url.Values)
	values.Set("prompt", url.QueryEscape(prompt))

	url := url.URL{
		Path:     "/device",
		RawQuery: values.Encode(),
	}
	http.Redirect(w, r, url.String(), http.StatusSeeOther)
}

const userCodeCookieName = "user_code"

type userCodeCookie struct {
	UserCode string
	UserName string
}

func (d *deviceLogin) loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		redirectBack(w, r, err.Error())
		return
	}

	userCode := r.PostForm.Get("user_code")
	if userCode == "" {
		redirectBack(w, r, "missing user_code in request")
		return
	}
	username := r.PostForm.Get("username")
	if username == "" {
		redirectBack(w, r, "missing username in request")
		return
	}
	password := r.PostForm.Get("password")
	if password == "" {
		redirectBack(w, r, "missing password in request")
		return
	}

	if err := d.storage.CheckUsernamePasswordSimple(username, password); err != nil {
		redirectBack(w, r, err.Error())
		return
	}
	state, err := d.storage.GetDeviceAuthorizationByUserCode(r.Context(), userCode)
	if err != nil {
		redirectBack(w, r, err.Error())
		return
	}

	encoded, err := d.cookie.Encode(userCodeCookieName, userCodeCookie{userCode, username})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:  userCodeCookieName,
		Value: encoded,
		Path:  "/",
	}
	http.SetCookie(w, cookie)
	renderConfirmPage(w, username, state.ClientID, state.Scopes)
}

func (d *deviceLogin) confirmHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(userCodeCookieName)
	if err != nil {
		redirectBack(w, r, err.Error())
		return
	}
	data := new(userCodeCookie)
	if err = d.cookie.Decode(userCodeCookieName, cookie.Value, &data); err != nil {
		redirectBack(w, r, err.Error())
		return
	}
	if err = r.ParseForm(); err != nil {
		redirectBack(w, r, err.Error())
		return
	}

	action := r.Form.Get("action")
	switch action {
	case "allowed":
		err = d.storage.CompleteDeviceAuthorization(r.Context(), data.UserCode, data.UserName)
	case "denied":
		err = d.storage.DenyDeviceAuthorization(r.Context(), data.UserCode)
	default:
		err = errors.New("action must be one of \"allow\" or \"deny\"")
	}
	if err != nil {
		redirectBack(w, r, err.Error())
		return
	}

	fmt.Fprintf(w, "Device authorization %s. You can now return to the device", action)
}
