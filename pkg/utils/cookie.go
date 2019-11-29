package utils

import (
	"errors"
	"net/http"

	"github.com/gorilla/securecookie"
)

type CookieHandler struct {
	securecookie *securecookie.SecureCookie
	secureOnly   bool
	sameSite     http.SameSite
	maxAge       int
	domain       string
}

func NewCookieHandler(hashKey, encryptKey []byte, opts ...CookieHandlerOpt) *CookieHandler {
	c := &CookieHandler{
		securecookie: securecookie.New(hashKey, encryptKey),
		secureOnly:   true,
		sameSite:     http.SameSiteNoneMode,
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
		c.securecookie.MaxAge(maxAge)
	}
}

func WithDomain(domain string) CookieHandlerOpt {
	return func(c *CookieHandler) {
		c.domain = domain
	}
}

func (c *CookieHandler) CheckQueryCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	var value string
	if err := c.securecookie.Decode(name, cookie.Value, &value); err != nil {
		return "", err
	}
	if value != r.FormValue(name) {
		return "", errors.New(name + " does not compare")
	}
	return value, nil
}

func (c *CookieHandler) SetQueryCookie(w http.ResponseWriter, name, value string) error {
	encoded, err := c.securecookie.Encode(name, value)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    encoded,
		Domain:   c.domain,
		Path:     "/",
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
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secureOnly,
		SameSite: c.sameSite,
	})
}