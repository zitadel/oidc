package internal

import (
	"time"

	"golang.org/x/text/language"

	"github.com/caos/oidc/pkg/op"

	"github.com/caos/oidc/pkg/oidc"
)

const (
	//CustomScope is an example for how to use custom scopes in this library
	//(in this scenario, when requested, it will return a custom claim)
	CustomScope = "custom_scope"

	//CustomClaim is an example for how to return custom claims with this library
	CustomClaim = "custom_claim"
)

type AuthRequest struct {
	ID            string
	CreationDate  time.Time
	ApplicationID string
	CallbackURI   string
	TransferState string
	Prompt        []Prompt
	UiLocales     []language.Tag
	LoginHint     string
	MaxAuthAge    *time.Duration
	UserID        string
	Scopes        []string
	ResponseType  OIDCResponseType
	Nonce         string
	CodeChallenge *OIDCCodeChallenge

	passwordChecked bool
	authTime        time.Time
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetACR() string {
	return "" //we won't handle acr in this example
}

func (a *AuthRequest) GetAMR() []string {
	//this example only uses password for authentication
	if a.passwordChecked {
		return []string{"pwd"}
	}
	return nil
}

func (a *AuthRequest) GetAudience() []string {
	return []string{a.ApplicationID} //this example will always just use the client_id as audience
}

func (a *AuthRequest) GetAuthTime() time.Time {
	return a.authTime
}

func (a *AuthRequest) GetClientID() string {
	return a.ApplicationID
}

func (a *AuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	return CodeChallengeToOIDC(a.CodeChallenge)
}

func (a *AuthRequest) GetNonce() string {
	return a.Nonce
}

func (a *AuthRequest) GetRedirectURI() string {
	return a.CallbackURI
}

func (a *AuthRequest) GetResponseType() oidc.ResponseType {
	return ResponseTypeToOIDC(a.ResponseType)
}

func (a *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return "" //we won't handle response mode in this example
}

func (a *AuthRequest) GetScopes() []string {
	return a.Scopes
}

func (a *AuthRequest) GetState() string {
	return a.TransferState
}

func (a *AuthRequest) GetSubject() string {
	return a.UserID
}

func (a *AuthRequest) Done() bool {
	return a.passwordChecked //this example only uses password for authentication
}

type Prompt int32

const (
	PromptUnspecified Prompt = iota
	PromptNone
	PromptLogin
	PromptConsent
	PromptSelectAccount
)

func PromptToInternal(oidcPrompt oidc.SpaceDelimitedArray) []Prompt {
	prompts := make([]Prompt, len(oidcPrompt))
	for _, oidcPrompt := range oidcPrompt {
		switch oidcPrompt {
		case oidc.PromptNone:
			prompts = append(prompts, PromptNone)
		case oidc.PromptLogin:
			prompts = append(prompts, PromptLogin)
		case oidc.PromptConsent:
			prompts = append(prompts, PromptConsent)
		case oidc.PromptSelectAccount:
			prompts = append(prompts, PromptSelectAccount)
		}
	}
	return prompts
}

type OIDCResponseType int32

const (
	OIDCResponseTypeCode OIDCResponseType = iota
	OIDCResponseTypeIDToken
	OIDCResponseTypeIDTokenToken
)

func ResponseTypeToInternal(responseType oidc.ResponseType) OIDCResponseType {
	switch responseType {
	case oidc.ResponseTypeCode:
		return OIDCResponseTypeCode
	case oidc.ResponseTypeIDTokenOnly:
		return OIDCResponseTypeIDToken
	case oidc.ResponseTypeIDToken:
		return OIDCResponseTypeIDTokenToken
	default:
		return OIDCResponseTypeCode
	}
}

func MaxAgeToInternal(maxAge *uint) *time.Duration {
	if maxAge == nil {
		return nil
	}
	dur := time.Duration(*maxAge) * time.Second
	return &dur
}

type AuthRequestOIDC struct {
	Scopes        []string
	ResponseType  interface{}
	Nonce         string
	CodeChallenge *OIDCCodeChallenge
}

func authRequestToInternal(authReq *oidc.AuthRequest, userID string) *AuthRequest {
	return &AuthRequest{
		CreationDate:  time.Now(),
		ApplicationID: authReq.ClientID,
		CallbackURI:   authReq.RedirectURI,
		TransferState: authReq.State,
		Prompt:        PromptToInternal(authReq.Prompt),
		UiLocales:     authReq.UILocales,
		LoginHint:     authReq.LoginHint,
		MaxAuthAge:    MaxAgeToInternal(authReq.MaxAge),
		UserID:        userID,
		Scopes:        authReq.Scopes,
		ResponseType:  ResponseTypeToInternal(authReq.ResponseType),
		Nonce:         authReq.Nonce,
		CodeChallenge: &OIDCCodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    string(authReq.CodeChallengeMethod),
		},
	}
}

type OIDCCodeChallenge struct {
	Challenge string
	Method    string
}

func CodeChallengeToOIDC(challenge *OIDCCodeChallenge) *oidc.CodeChallenge {
	if challenge == nil {
		return nil
	}
	challengeMethod := oidc.CodeChallengeMethodPlain
	if challenge.Method == "S256" {
		challengeMethod = oidc.CodeChallengeMethodS256
	}
	return &oidc.CodeChallenge{
		Challenge: challenge.Challenge,
		Method:    challengeMethod,
	}
}

func ResponseTypeToOIDC(responseType OIDCResponseType) oidc.ResponseType {
	switch responseType {
	case OIDCResponseTypeCode:
		return oidc.ResponseTypeCode
	case OIDCResponseTypeIDTokenToken:
		return oidc.ResponseTypeIDToken
	case OIDCResponseTypeIDToken:
		return oidc.ResponseTypeIDTokenOnly
	default:
		return oidc.ResponseTypeCode
	}
}

//RefreshTokenRequestFromBusiness will simply wrap the internal RefreshToken to implement the op.RefreshTokenRequest interface
func RefreshTokenRequestFromBusiness(token *RefreshToken) op.RefreshTokenRequest {
	return &RefreshTokenRequest{token}
}

type RefreshTokenRequest struct {
	*RefreshToken
}

func (r *RefreshTokenRequest) GetAMR() []string {
	return r.AMR
}

func (r *RefreshTokenRequest) GetAudience() []string {
	return r.Audience
}

func (r *RefreshTokenRequest) GetAuthTime() time.Time {
	return r.AuthTime
}

func (r *RefreshTokenRequest) GetClientID() string {
	return r.ApplicationID
}

func (r *RefreshTokenRequest) GetScopes() []string {
	return r.Scopes
}

func (r *RefreshTokenRequest) GetSubject() string {
	return r.UserID
}

func (r *RefreshTokenRequest) SetCurrentScopes(scopes []string) {
	r.Scopes = scopes
}
