package oidc

const (
	//ScopeOpenID defines the scope `openid`
	//OpenID Connect requests MUST contain the `openid` scope value
	ScopeOpenID = "openid"

	//ScopeProfile defines the scope `profile`
	//This (optional) scope value requests access to the End-User's default profile Claims,
	//which are: name, family_name, given_name, middle_name, nickname, preferred_username,
	//profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
	ScopeProfile = "profile"

	//ScopeEmail defines the scope `email`
	//This (optional) scope value requests access to the email and email_verified Claims.
	ScopeEmail = "email"

	//ScopeAddress defines the scope `address`
	//This (optional) scope value requests access to the address Claim.
	ScopeAddress = "address"

	//ScopePhone defines the scope `phone`
	//This (optional) scope value requests access to the phone_number and phone_number_verified Claims.
	ScopePhone = "phone"

	//ScopeOfflineAccess defines the scope `offline_access`
	//This (optional) scope value requests that an OAuth 2.0 Refresh Token be issued that can be used to obtain an Access Token
	//that grants access to the End-User's UserInfo Endpoint even when the End-User is not present (not logged in).
	ScopeOfflineAccess = "offline_access"

	//ResponseTypeCode for the Authorization Code Flow returning a code from the Authorization Server
	ResponseTypeCode ResponseType = "code"

	//ResponseTypeIDToken for the Implicit Flow returning id and access tokens directly from the Authorization Server
	ResponseTypeIDToken ResponseType = "id_token token"

	//ResponseTypeIDTokenOnly for the Implicit Flow returning only id token directly from the Authorization Server
	ResponseTypeIDTokenOnly ResponseType = "id_token"

	DisplayPage  Display = "page"
	DisplayPopup Display = "popup"
	DisplayTouch Display = "touch"
	DisplayWAP   Display = "wap"

	//PromptNone (`none`) disallows the Authorization Server to display any authentication or consent user interface pages.
	//An error (login_required, interaction_required, ...) will be returned if the user is not already authenticated or consent is needed
	PromptNone Prompt = "none"

	//PromptLogin (`login`) directs the Authorization Server to prompt the End-User for reauthentication.
	PromptLogin Prompt = "login"

	//PromptConsent (`consent`) directs the Authorization Server to prompt the End-User for consent (of sharing information).
	PromptConsent Prompt = "consent"

	//PromptSelectAccount (`select_account `) directs the Authorization Server to prompt the End-User to select a user account (to enable multi user / session switching)
	PromptSelectAccount Prompt = "select_account"
)

//AuthRequest according to:
//https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
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

//GetRedirectURI returns the redirect_uri value for the ErrAuthRequest interface
func (a *AuthRequest) GetRedirectURI() string {
	return a.RedirectURI
}

//GetResponseType returns the response_type value for the ErrAuthRequest interface
func (a *AuthRequest) GetResponseType() ResponseType {
	return a.ResponseType
}

//GetState returns the optional state value for the ErrAuthRequest interface
func (a *AuthRequest) GetState() string {
	return a.State
}
