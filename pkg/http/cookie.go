package http

import (
	"errors"
	"net/http"

	"github.com/gorilla/securecookie"
)

type CookieHandler struct {
	securecookie     *securecookie.SecureCookie
	secureCookieFunc func(r *http.Request) (*securecookie.SecureCookie, error)
	secureOnly       bool
	sameSite         http.SameSite
	maxAge           int
	domain           string
	path             string
}

func NewCookieHandler(hashKey, encryptKey []byte, opts ...CookieHandlerOpt) *CookieHandler {
	c := &CookieHandler{
		securecookie: securecookie.New(hashKey, encryptKey),
		secureOnly:   true,
		sameSite:     http.SameSiteLaxMode,
		path:         "/",
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}

func NewRequestAwareCookieHandler(secureCookieFunc func(r *http.Request) (*securecookie.SecureCookie, error), opts ...CookieHandlerOpt) *CookieHandler {
	c := &CookieHandler{
		secureCookieFunc: secureCookieFunc,
		secureOnly:       true,
		sameSite:         http.SameSiteLaxMode,
		path:             "/",
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type CookieHandlerOpt func(*CookieHandler)

func WithUnsecure() CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.secureOnly = false
	}
}

func WithSameSite(sameSite http.SameSite) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.sameSite = sameSite
	}
}

func WithMaxAge(maxAge int) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.maxAge = maxAge
		if c.IsRequestAware() {
			return
		}

		c.securecookie.MaxAge(maxAge)
	}
}

func WithDomain(domain string) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.domain = domain
	}
}

func WithPath(path string) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.path = path
	}
}

func (c *CookieHandler) CheckCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	secureCookie := c.securecookie
	if c.IsRequestAware() {
		secureCookie, err = c.secureCookieFunc(r)
		if err != nil {
			return "", err
		}
	}

	var value string
	if err := secureCookie.Decode(name, cookie.Value, &value); err != nil {
		return "", err
	}
	return value, nil
}

func (c *CookieHandler) CheckQueryCookie(r *http.Request, name string) (string, error) {
	value, err := c.CheckCookie(r, name)
	if err != nil {
		return "", err
	}
	if value != r.FormValue(name) {
		return "", errors.New(name + " does not compare")
	}
	return value, nil
}

func (c *CookieHandler) SetCookie(w http.ResponseWriter, name, value string) error {
	if c.IsRequestAware() {
		return errors.New("Cookie handler is request aware")
	}

	encoded, err := c.securecookie.Encode(name, value)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encoded,
		Domain:   c.domain,
		Path:     c.path,
		MaxAge:   c.maxAge,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	})
	return nil
}

func (c *CookieHandler) SetRequestAwareCookie(r *http.Request, w http.ResponseWriter, name string, value string) error {
	if !c.IsRequestAware() {
		return errors.New("Cookie handler is not request aware")
	}

	secureCookie, err := c.secureCookieFunc(r)
	if err != nil {
		return err
	}

	encoded, err := secureCookie.Encode(name, value)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encoded,
		Domain:   c.domain,
		Path:     c.path,
		MaxAge:   c.maxAge,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	})

	return nil
}

func (c *CookieHandler) DeleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Domain:   c.domain,
		Path:     c.path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	})
}

func (c *CookieHandler) IsRequestAware() bool {
	return c.secureCookieFunc != nil
}
