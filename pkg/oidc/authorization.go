package oidc

import (
	"errors"
	"strings"

	"golang.org/x/text/language"
)

const (
	ResponseTypeCode        = "code"
	ResponseTypeIDToken     = "id_token token"
	ResponseTypeIDTokenOnly = "id_token"

	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWAP   Display = "wap"

	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

var displayValues = map[string]Display{
	"page":  DisplayPage,
	"popup": DisplayPopup,
	"touch": DisplayTouch,
	"wap":   DisplayWAP,
}

//AuthRequest according to:
//https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//
type AuthRequest struct {
	Scopes       Scopes       `schema:"scope"`
	ResponseType ResponseType `schema:"response_type"`
	ClientID     string       `schema:"client_id"`
	RedirectURI  string       `schema:"redirect_uri"` //TODO: type

	State string `schema:"state"`

	// ResponseMode TODO: ?

	Nonce       string   `schema:"nonce"`
	Display     Display  `schema:"display"`
	Prompt      Prompt   `schema:"prompt"`
	MaxAge      uint32   `schema:"max_age"`
	UILocales   Locales  `schema:"ui_locales"`
	IDTokenHint string   `schema:"id_token_hint"`
	LoginHint   string   `schema:"login_hint"`
	ACRValues   []string `schema:"acr_values"`
}

type Scopes []string

func (s *Scopes) UnmarshalText(text []byte) error {
	scopes := strings.Split(string(text), " ")
	*s = Scopes(scopes)
	return nil
}

type ResponseType string

type Display string

func (d *Display) UnmarshalText(text []byte) error {
	var ok bool
	display := string(text)
	*d, ok = displayValues[display]
	if !ok {
		return errors.New("")
	}
	return nil
}

type Prompt string

type Locales []language.Tag

func (l *Locales) UnmarshalText(text []byte) error {
	locales := strings.Split(string(text), " ")
	for _, locale := range locales {
		tag, err := language.Parse(locale)
		if err == nil && !tag.IsRoot() {
			*l = append(*l, tag)
		}
	}
	return nil
}
