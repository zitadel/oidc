package oidc

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/text/language"
)

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

	//GrantTypeCode defines the grant_type `authorization_code` used for the Token Request in the Authorization Code Flow
	GrantTypeCode GrantType = "authorization_code"
	//GrantTypeBearer define the grant_type `urn:ietf:params:oauth:grant-type:jwt-bearer` used for the JWT Authorization Grant
	GrantTypeBearer GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	//BearerToken defines the token_type `Bearer`, which is returned in a successful token response
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

type JWTTokenRequest struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Scopes    Scopes `json:"scope"`
	Audience  string `json:"aud"`
	IssuedAt  Time   `json:"iat"`
	ExpiresAt Time   `json:"exp"`
}

func (j *JWTTokenRequest) GetClientID() string {
	return j.Subject
}

func (j *JWTTokenRequest) GetSubject() string {
	return j.Subject
}

func (j *JWTTokenRequest) GetScopes() []string {
	return j.Scopes
}

type Time time.Time

func (t *Time) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	*t = Time(time.Unix(i, 0).UTC())
	return nil
}

func (j *JWTTokenRequest) GetIssuer() string {
	return j.Issuer
}

func (j *JWTTokenRequest) GetAudience() []string {
	return []string{j.Audience}
}

func (j *JWTTokenRequest) GetExpiration() time.Time {
	return time.Time(j.ExpiresAt)
}

func (j *JWTTokenRequest) GetIssuedAt() time.Time {
	return time.Time(j.IssuedAt)
}

func (j *JWTTokenRequest) GetNonce() string {
	return ""
}

func (j *JWTTokenRequest) GetAuthenticationContextClassReference() string {
	return ""
}

func (j *JWTTokenRequest) GetAuthTime() time.Time {
	return time.Time{}
}

func (j *JWTTokenRequest) GetAuthorizedParty() string {
	return ""
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
