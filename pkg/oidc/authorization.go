package oidc

import (
	"log/slog"
)

const (
	// ScopeOpenID defines the scope `openid`
	// OpenID Connect requests MUST contain the `openid` scope value
	ScopeOpenID = "openid"

	// ScopeProfile defines the scope `profile`
	// This (optional) scope value requests access to the End-User's default profile Claims,
	// which are: name, family_name, given_name, middle_name, nickname, preferred_username,
	// profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
	ScopeProfile = "profile"

	// ScopeEmail defines the scope `email`
	// This (optional) scope value requests access to the email and email_verified Claims.
	ScopeEmail = "email"

	// ScopeAddress defines the scope `address`
	// This (optional) scope value requests access to the address Claim.
	ScopeAddress = "address"

	// ScopePhone defines the scope `phone`
	// This (optional) scope value requests access to the phone_number and phone_number_verified Claims.
	ScopePhone = "phone"

	// ScopeOfflineAccess defines the scope `offline_access`
	// This (optional) scope value requests that an OAuth 2.0 Refresh Token be issued that can be used to obtain an Access Token
	// that grants access to the End-User's UserInfo Endpoint even when the End-User is not present (not logged in).
	ScopeOfflineAccess = "offline_access"

	// ResponseTypeCode for the Authorization Code Flow returning a code from the Authorization Server
	ResponseTypeCode ResponseType = "code"

	// ResponseTypeIDToken for the Implicit Flow returning id and access tokens directly from the Authorization Server
	ResponseTypeIDToken ResponseType = "id_token token"

	// ResponseTypeIDTokenOnly for the Implicit Flow returning only id token directly from the Authorization Server
	ResponseTypeIDTokenOnly ResponseType = "id_token"

	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWAP   Display = "wap"

	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFragment ResponseMode = "fragment"
	ResponseModeFormPost ResponseMode = "form_post"

	// PromptNone (`none`) disallows the Authorization Server to display any authentication or consent user interface pages.
	// An error (login_required, interaction_required, ...) will be returned if the user is not already authenticated or consent is needed
	PromptNone = "none"

	// PromptLogin (`login`) directs the Authorization Server to prompt the End-User for reauthentication.
	PromptLogin = "login"

	// PromptConsent (`consent`) directs the Authorization Server to prompt the End-User for consent (of sharing information).
	PromptConsent = "consent"

	// PromptSelectAccount (`select_account `) directs the Authorization Server to prompt the End-User to select a user account (to enable multi user / session switching)
	PromptSelectAccount = "select_account"
)

// AuthRequest according to:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthRequest struct {
	Scopes       SpaceDelimitedArray `json:"scope" schema:"scope"`
	ResponseType ResponseType        `json:"response_type" schema:"response_type"`
	ClientID     string              `json:"client_id" schema:"client_id"`
	RedirectURI  string              `json:"redirect_uri" schema:"redirect_uri"`

	State string `json:"state" schema:"state"`
	Nonce string `json:"nonce" schema:"nonce"`

	ResponseMode ResponseMode        `json:"response_mode" schema:"response_mode"`
	Display      Display             `json:"display" schema:"display"`
	Prompt       SpaceDelimitedArray `json:"prompt" schema:"prompt"`
	MaxAge       *uint               `json:"max_age" schema:"max_age"`
	UILocales    Locales             `json:"ui_locales" schema:"ui_locales"`
	IDTokenHint  string              `json:"id_token_hint" schema:"id_token_hint"`
	LoginHint    string              `json:"login_hint" schema:"login_hint"`
	ACRValues    SpaceDelimitedArray `json:"acr_values" schema:"acr_values"`

	CodeChallenge       string              `json:"code_challenge" schema:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method" schema:"code_challenge_method"`

	// RequestParam enables OIDC requests to be passed in a single, self-contained parameter (as JWT, called Request Object)
	RequestParam string `schema:"request"`
}

func (a *AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("scopes", a.Scopes),
		slog.String("response_type", string(a.ResponseType)),
		slog.String("client_id", a.ClientID),
		slog.String("redirect_uri", a.RedirectURI),
	)
}

// GetRedirectURI returns the redirect_uri value for the ErrAuthRequest interface
func (a *AuthRequest) GetRedirectURI() string {
	return a.RedirectURI
}

// GetResponseType returns the response_type value for the ErrAuthRequest interface
func (a *AuthRequest) GetResponseType() ResponseType {
	return a.ResponseType
}

// GetState returns the optional state value for the ErrAuthRequest interface
func (a *AuthRequest) GetState() string {
	return a.State
}

// GetResponseMode returns the optional ResponseMode
func (a *AuthRequest) GetResponseMode() ResponseMode {
	return a.ResponseMode
}
