package oidc

import (
	"golang.org/x/text/language"
)

const (
	ResponseTypeCode        = "code"
	ResponseTypeIDToken     = "id_token token"
	ResponseTypeIDTokenOnly = "id_token"

	DisplayPage  = "page"
	DisplayPopup = "popup"
	DisplayTouch = "touch"
	DisplayWAP   = "wap"

	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

//AuthRequest according to:
//https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//
type AuthRequest struct {
	Scopes       []string     `schema:"scope"`
	ResponseType ResponseType `schema:"response_type"`
	ClientID     string
	RedirectURI  string //TODO: type

	State string

	// ResponseMode TODO: ?

	Nonce       string
	Display     Display
	Prompt      Prompt
	MaxAge      uint32
	UILocales   []language.Tag
	IDTokenHint string
	LoginHint   string
	ACRValues   []string
}

type ResponseType string

type Display string

type Prompt string
