package oidc

import (
	"errors"
	"strings"

	"golang.org/x/text/language"
)

const (
	ScopeOpenID = "openid"

	ResponseTypeCode        ResponseType = "code"
	ResponseTypeIDToken     ResponseType = "id_token token"
	ResponseTypeIDTokenOnly ResponseType = "id_token"

	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWAP   Display = "wap"

	PromptNone          Prompt = "none"
	PromptLogin         Prompt = "login"
	PromptConsent       Prompt = "consent"
	PromptSelectAccount Prompt = "select_account"

	GrantTypeCode GrantType = "authorization_code"

	BearerToken = "Bearer"
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
	ID           string
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

	CodeChallenge       string              `schema:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `schema:"code_challenge_method"`
}

func (a *AuthRequest) GetRedirectURI() string {
	return a.RedirectURI
}
func (a *AuthRequest) GetResponseType() ResponseType {
	return a.ResponseType
}
func (a *AuthRequest) GetState() string {
	return a.State
}

type TokenRequest interface {
	// GrantType GrantType `schema:"grant_type"`
	GrantType() GrantType
}

type TokenRequestType GrantType

type AccessTokenRequest struct {
	Code         string `schema:"code"`
	RedirectURI  string `schema:"redirect_uri"`
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
	CodeVerifier string `schema:"code_verifier"`
}

func (a *AccessTokenRequest) GrantType() GrantType {
	return GrantTypeCode
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty" schema:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty" schema:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty" schema:"refresh_token,omitempty"`
	ExpiresIn    uint64 `json:"expires_in,omitempty" schema:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty" schema:"id_token,omitempty"`
}

type TokenExchangeRequest struct {
	subjectToken       string   `schema:"subject_token"`
	subjectTokenType   string   `schema:"subject_token_type"`
	actorToken         string   `schema:"actor_token"`
	actorTokenType     string   `schema:"actor_token_type"`
	resource           []string `schema:"resource"`
	audience           []string `schema:"audience"`
	Scope              []string `schema:"scope"`
	requestedTokenType string   `schema:"requested_token_type"`
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

type GrantType string
