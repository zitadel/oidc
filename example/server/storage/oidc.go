package storage

import (
	"log/slog"
	"slices"
	"time"

	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const (
	// CustomScope is an example for how to use custom scopes in this library
	//(in this scenario, when requested, it will return a custom claim)
	CustomScope = "custom_scope"

	// CustomClaim is an example for how to return custom claims with this library
	CustomClaim = "custom_claim"

	// CustomScopeImpersonatePrefix is an example scope prefix for passing user id to impersonate using token exchange
	CustomScopeImpersonatePrefix = "custom_scope:impersonate:"
)

type AuthRequest struct {
	ID            string
	CreationDate  time.Time
	ApplicationID string
	CallbackURI   string
	TransferState string
	Prompt        []string
	UiLocales     []language.Tag
	LoginHint     string
	MaxAuthAge    *time.Duration
	UserID        string
	Scopes        []string
	ResponseType  oidc.ResponseType
	ResponseMode  oidc.ResponseMode
	Nonce         string
	CodeChallenge *OIDCCodeChallenge

	// Resource holds the resource indicators (RFC 8707) requested by the client.
	// A token request may narrow them down for the access token, see
	// SetCurrentResources, but the grant itself is kept for the refresh token.
	Resource []string

	done             bool
	authTime         time.Time
	currentResources []string
}

// LogValue allows you to define which fields will be logged.
// Implements the [slog.LogValuer]
func (a *AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", a.ID),
		slog.Time("creation_date", a.CreationDate),
		slog.Any("scopes", a.Scopes),
		slog.String("response_type", string(a.ResponseType)),
		slog.String("app_id", a.ApplicationID),
		slog.String("callback_uri", a.CallbackURI),
	)
}

func (a *AuthRequest) GetID() string {
	return a.ID
}

func (a *AuthRequest) GetACR() string {
	return "" // we won't handle acr in this example
}

func (a *AuthRequest) GetAMR() []string {
	// this example only uses password for authentication
	if a.done {
		return []string{"pwd"}
	}
	return nil
}

// GetAudience is the audience of the ID token, which is always just the client_id.
func (a *AuthRequest) GetAudience() []string {
	return []string{a.ApplicationID}
}

// GetAccessTokenAudience implements the optional op.AccessTokenAudienceRequest
// interface: unlike the ID token, the access token is addressed to the requested
// resources as well.
func (a *AuthRequest) GetAccessTokenAudience() []string {
	return accessTokenAudience(a.GetAudience(), a.Resource, a.currentResources)
}

// GetResource implements the optional op.ResourceRequest interface, which lets the
// op package check a `resource` parameter of a token request against the resources
// that were requested at the authorization endpoint.
func (a *AuthRequest) GetResource() []string {
	return a.Resource
}

// SetCurrentResources implements the optional op.CurrentResourceSetter interface.
// It is called with the `resource` values of a token request, after they have been
// checked against the resources of the authorization request, so that the audience
// of the access token can be narrowed down to them.
func (a *AuthRequest) SetCurrentResources(resources []string) {
	a.currentResources = resources
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
	return a.ResponseType
}

func (a *AuthRequest) GetResponseMode() oidc.ResponseMode {
	return a.ResponseMode
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
	return a.done
}

func PromptToInternal(oidcPrompt oidc.SpaceDelimitedArray) []string {
	prompts := make([]string, 0, len(oidcPrompt))
	for _, oidcPrompt := range oidcPrompt {
		switch oidcPrompt {
		case oidc.PromptNone,
			oidc.PromptLogin,
			oidc.PromptConsent,
			oidc.PromptSelectAccount:
			prompts = append(prompts, oidcPrompt)
		}
	}
	return prompts
}

func MaxAgeToInternal(maxAge *uint) *time.Duration {
	if maxAge == nil {
		return nil
	}
	dur := time.Duration(*maxAge) * time.Second
	return &dur
}

func authRequestToInternal(authReq *oidc.AuthRequest, userID string) *AuthRequest {
	var codeChallenge *OIDCCodeChallenge
	if authReq.CodeChallenge != "" {
		codeChallenge = &OIDCCodeChallenge{
			Challenge: authReq.CodeChallenge,
			Method:    string(authReq.CodeChallengeMethod),
		}
	}

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
		ResponseType:  authReq.ResponseType,
		ResponseMode:  authReq.ResponseMode,
		Nonce:         authReq.Nonce,
		CodeChallenge: codeChallenge,
		Resource:      authReq.Resource,
	}
}

type AuthRequestWithSessionState struct {
	*AuthRequest
	SessionState string
}

func (a *AuthRequestWithSessionState) GetSessionState() string {
	return a.SessionState
}

type OIDCCodeChallenge struct {
	Challenge string
	Method    string
}

func CodeChallengeToOIDC(challenge *OIDCCodeChallenge) *oidc.CodeChallenge {
	if challenge == nil {
		return nil
	}
	// Pass the method through, so that oidc.VerifyCodeChallenge refuses an
	// unsupported one instead of it being verified as plain.
	return &oidc.CodeChallenge{
		Challenge: challenge.Challenge,
		Method:    oidc.CodeChallengeMethod(challenge.Method),
	}
}

// RefreshTokenRequestFromBusiness will simply wrap the storage RefreshToken to implement the op.RefreshTokenRequest interface
func RefreshTokenRequestFromBusiness(token *RefreshToken) op.RefreshTokenRequest {
	return &RefreshTokenRequest{RefreshToken: token}
}

type RefreshTokenRequest struct {
	*RefreshToken

	// currentResources is kept on the request instead of the stored refresh token,
	// as narrowing the resources of one refresh request must not change the grant.
	currentResources []string
}

func (r *RefreshTokenRequest) GetAMR() []string {
	return r.AMR
}

// GetAudience is the audience of the ID token.
func (r *RefreshTokenRequest) GetAudience() []string {
	return r.Audience
}

// GetAccessTokenAudience implements the optional op.AccessTokenAudienceRequest
// interface, see AuthRequest.GetAccessTokenAudience.
func (r *RefreshTokenRequest) GetAccessTokenAudience() []string {
	return accessTokenAudience(r.Audience, r.Resource, r.currentResources)
}

// GetResource implements the optional op.ResourceRequest interface. It reports the
// resources of the original grant, which a refresh request may only narrow down.
func (r *RefreshTokenRequest) GetResource() []string {
	return r.Resource
}

// SetCurrentResources implements the optional op.CurrentResourceSetter interface.
func (r *RefreshTokenRequest) SetCurrentResources(resources []string) {
	r.currentResources = resources
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

// accessTokenAudience shows how a Storage implementation can bind the audience of
// the access token to the resource indicators of [RFC 8707]: the resources a token
// request narrowed the grant to, or else all granted resources, are added to the
// audience of the ID token.
//
// The client_id is kept in the access token audience, so that the existing
// behaviour of the example, such as introspection by the client itself, does not
// change. A real implementation would check the requested resources against a
// policy of the client, and could restrict the audience to the resources alone.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
func accessTokenAudience(audience, granted, current []string) []string {
	resources := granted
	if len(current) > 0 {
		resources = current
	}
	result := slices.Clone(audience)
	for _, resource := range resources {
		if !slices.Contains(result, resource) {
			result = append(result, resource)
		}
	}
	return result
}

// grantedResources returns the resource indicators of [RFC 8707] granted to a
// token request, if the request reports any. A refresh token is bound to them.
//
// [RFC 8707]: https://www.rfc-editor.org/rfc/rfc8707
func grantedResources(request op.TokenRequest) []string {
	if resourceRequest, ok := request.(op.ResourceRequest); ok {
		return resourceRequest.GetResource()
	}
	return nil
}
