package op

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AuthRequest interface {
	GetID() string
	GetACR() string
	GetAMR() []string
	GetAudience() []string
	GetAuthTime() time.Time
	GetClientID() string
	GetCodeChallenge() *oidc.CodeChallenge
	GetNonce() string
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetResponseMode() oidc.ResponseMode
	GetScopes() []string
	GetState() string
	GetSubject() string
	Done() bool
}

// AuthRequestSessionState should be implemented if [OpenID Connect Session Management](https://openid.net/specs/openid-connect-session-1_0.html) is supported
type AuthRequestSessionState interface {
	// GetSessionState returns session_state.
	// session_state is related to OpenID Connect Session Management.
	GetSessionState() string
}

type Authorizer interface {
	Storage() Storage
	Decoder() httphelper.Decoder
	Encoder() httphelper.Encoder
	IDTokenHintVerifier(context.Context) *IDTokenHintVerifier
	Crypto() Crypto
	RequestObjectSupported() bool
	Logger() *slog.Logger
}

// AuthorizeValidator is an extension of Authorizer interface
// implementing its own validation mechanism for the auth request
type AuthorizeValidator interface {
	Authorizer
	ValidateAuthRequest(context.Context, *oidc.AuthRequest, Storage, *IDTokenHintVerifier) (string, error)
}

type CodeResponseType struct {
	Code         string `schema:"code"`
	State        string `schema:"state,omitempty"`
	SessionState string `schema:"session_state,omitempty"`
}

func authorizeHandler(authorizer Authorizer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Authorize(w, r, authorizer)
	}
}

func AuthorizeCallbackHandler(authorizer Authorizer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AuthorizeCallback(w, r, authorizer)
	}
}

// Authorize handles the authorization request, including
// parsing, validating, storing and finally redirecting to the login handler
func Authorize(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	ctx, span := tracer.Start(r.Context(), "Authorize")
	r = r.WithContext(ctx)
	defer span.End()

	authReq, err := ParseAuthorizeRequest(r, authorizer.Decoder())
	if err != nil {
		AuthRequestError(w, r, nil, err, authorizer)
		return
	}
	if authReq.RequestParam != "" && authorizer.RequestObjectSupported() {
		err = ParseRequestObject(ctx, authReq, authorizer.Storage(), IssuerFromContext(ctx))
		if err != nil {
			AuthRequestError(w, r, nil, err, authorizer)
			return
		}
	}
	if authReq.ClientID == "" {
		AuthRequestError(w, r, nil, fmt.Errorf("auth request is missing client_id"), authorizer)
		return
	}
	if authReq.RedirectURI == "" {
		AuthRequestError(w, r, nil, fmt.Errorf("auth request is missing redirect_uri"), authorizer)
		return
	}

	var client Client
	validation := func(ctx context.Context, authReq *oidc.AuthRequest, storage Storage, verifier *IDTokenHintVerifier) (sub string, err error) {
		client, err = authorizer.Storage().GetClientByClientID(ctx, authReq.ClientID)
		if err != nil {
			return "", oidc.ErrInvalidRequestRedirectURI().WithDescription("unable to retrieve client by id").WithParent(err)
		}
		return ValidateAuthRequestClient(ctx, authReq, client, verifier)
	}
	if validator, ok := authorizer.(AuthorizeValidator); ok {
		validation = validator.ValidateAuthRequest
	}
	userID, err := validation(ctx, authReq, authorizer.Storage(), authorizer.IDTokenHintVerifier(ctx))
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer)
		return
	}
	if authReq.RequestParam != "" {
		AuthRequestError(w, r, authReq, oidc.ErrRequestNotSupported(), authorizer)
		return
	}
	req, err := authorizer.Storage().CreateAuthRequest(ctx, authReq, userID)
	if err != nil {
		AuthRequestError(w, r, authReq, oidc.DefaultToServerError(err, "unable to save auth request"), authorizer)
		return
	}
	RedirectToLogin(req.GetID(), client, w, r)
}

// ParseAuthorizeRequest parsed the http request into an oidc.AuthRequest
func ParseAuthorizeRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.AuthRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse form").WithParent(err)
	}
	authReq := new(oidc.AuthRequest)
	err = decoder.Decode(authReq, r.Form)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("cannot parse auth request").WithParent(err)
	}
	return authReq, nil
}

// ParseRequestObject parse the `request` parameter, validates the token including the signature
// and copies the token claims into the auth request
func ParseRequestObject(ctx context.Context, authReq *oidc.AuthRequest, storage Storage, issuer string) error {
	requestObject := new(oidc.RequestObject)
	payload, err := oidc.ParseToken(authReq.RequestParam, requestObject)
	if err != nil {
		return err
	}

	if requestObject.ClientID != "" && requestObject.ClientID != authReq.ClientID {
		return oidc.ErrInvalidRequest().WithDescription("missing or wrong client id in request")
	}
	if requestObject.ResponseType != "" && requestObject.ResponseType != authReq.ResponseType {
		return oidc.ErrInvalidRequest().WithDescription("missing or wrong response type in request")
	}
	if requestObject.Issuer != requestObject.ClientID {
		return oidc.ErrInvalidRequest().WithDescription("missing or wrong issuer in request")
	}
	if !slices.Contains(requestObject.Audience, issuer) {
		return oidc.ErrInvalidRequest().WithDescription("issuer missing in audience")
	}
	keySet := &jwtProfileKeySet{storage: storage, clientID: requestObject.Issuer}
	if err = oidc.CheckSignature(ctx, authReq.RequestParam, payload, requestObject, nil, keySet); err != nil {
		return oidc.ErrInvalidRequest().WithParent(err).WithDescription(err.Error())
	}
	CopyRequestObjectToAuthRequest(authReq, requestObject)
	return nil
}

// CopyRequestObjectToAuthRequest overwrites present values from the Request Object into the auth request
// and clears the `RequestParam` of the auth request
func CopyRequestObjectToAuthRequest(authReq *oidc.AuthRequest, requestObject *oidc.RequestObject) {
	if slices.Contains(authReq.Scopes, oidc.ScopeOpenID) && len(requestObject.Scopes) > 0 {
		authReq.Scopes = requestObject.Scopes
	}
	if requestObject.RedirectURI != "" {
		authReq.RedirectURI = requestObject.RedirectURI
	}
	if requestObject.State != "" {
		authReq.State = requestObject.State
	}
	if requestObject.ResponseMode != "" {
		authReq.ResponseMode = requestObject.ResponseMode
	}
	if requestObject.Nonce != "" {
		authReq.Nonce = requestObject.Nonce
	}
	if requestObject.Display != "" {
		authReq.Display = requestObject.Display
	}
	if len(requestObject.Prompt) > 0 {
		authReq.Prompt = requestObject.Prompt
	}
	if requestObject.MaxAge != nil {
		authReq.MaxAge = requestObject.MaxAge
	}
	if len(requestObject.UILocales) > 0 {
		authReq.UILocales = requestObject.UILocales
	}
	if requestObject.IDTokenHint != "" {
		authReq.IDTokenHint = requestObject.IDTokenHint
	}
	if requestObject.LoginHint != "" {
		authReq.LoginHint = requestObject.LoginHint
	}
	if len(requestObject.ACRValues) > 0 {
		authReq.ACRValues = requestObject.ACRValues
	}
	if requestObject.CodeChallenge != "" {
		authReq.CodeChallenge = requestObject.CodeChallenge
	}
	if requestObject.CodeChallengeMethod != "" {
		authReq.CodeChallengeMethod = requestObject.CodeChallengeMethod
	}
	authReq.RequestParam = ""
}

// ValidateAuthRequest validates the authorize parameters and returns the userID of the id_token_hint if passed.
//
// Deprecated: Use [ValidateAuthRequestClient] to prevent querying for the Client twice.
func ValidateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, storage Storage, verifier *IDTokenHintVerifier) (sub string, err error) {
	ctx, span := tracer.Start(ctx, "ValidateAuthRequest")
	defer span.End()

	client, err := storage.GetClientByClientID(ctx, authReq.ClientID)
	if err != nil {
		return "", oidc.ErrInvalidRequestRedirectURI().WithDescription("unable to retrieve client by id").WithParent(err)
	}
	return ValidateAuthRequestClient(ctx, authReq, client, verifier)
}

// ValidateAuthRequestClient validates the Auth request against the passed client.
// If id_token_hint is part of the request, the subject of the token is returned.
func ValidateAuthRequestClient(ctx context.Context, authReq *oidc.AuthRequest, client Client, verifier *IDTokenHintVerifier) (sub string, err error) {
	ctx, span := tracer.Start(ctx, "ValidateAuthRequestClient")
	defer span.End()

	if err := ValidateAuthReqRedirectURI(client, authReq.RedirectURI, authReq.ResponseType); err != nil {
		return "", err
	}
	authReq.MaxAge, err = ValidateAuthReqPrompt(authReq.Prompt, authReq.MaxAge)
	if err != nil {
		return "", err
	}
	authReq.Scopes, err = ValidateAuthReqScopes(client, authReq.Scopes)
	if err != nil {
		return "", err
	}
	if err := ValidateAuthReqResponseType(client, authReq.ResponseType); err != nil {
		return "", err
	}
	return ValidateAuthReqIDTokenHint(ctx, authReq.IDTokenHint, verifier)
}

// ValidateAuthReqPrompt validates the passed prompt values and sets max_age to 0 if prompt login is present
func ValidateAuthReqPrompt(prompts []string, maxAge *uint) (_ *uint, err error) {
	for _, prompt := range prompts {
		if prompt == oidc.PromptNone && len(prompts) > 1 {
			return nil, oidc.ErrInvalidRequest().WithDescription("The prompt parameter `none` must only be used as a single value")
		}
		if prompt == oidc.PromptLogin {
			maxAge = oidc.NewMaxAge(0)
		}
	}
	return maxAge, nil
}

// ValidateAuthReqScopes validates the passed scopes and deletes any unsupported scopes.
// An error is returned if scopes is empty.
func ValidateAuthReqScopes(client Client, scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, oidc.ErrInvalidRequest().
			WithDescription("The scope of your request is missing. Please ensure some scopes are requested. " +
				"If you have any questions, you may contact the administrator of the application.")
	}
	scopes = slices.DeleteFunc(scopes, func(scope string) bool {
		return !(scope == oidc.ScopeOpenID ||
			scope == oidc.ScopeProfile ||
			scope == oidc.ScopeEmail ||
			scope == oidc.ScopePhone ||
			scope == oidc.ScopeAddress ||
			scope == oidc.ScopeOfflineAccess) &&
			!client.IsScopeAllowed(scope)
	})
	return scopes, nil
}

// checkURIAgainstRedirects just checks aginst the valid redirect URIs and ignores
// other factors.
func checkURIAgainstRedirects(client Client, uri string) error {
	if slices.Contains(client.RedirectURIs(), uri) {
		return nil
	}
	if globClient, ok := client.(HasRedirectGlobs); ok {
		for _, uriGlob := range globClient.RedirectURIGlobs() {
			isMatch, err := doublestar.Match(uriGlob, uri)
			if err != nil {
				return oidc.ErrServerError().WithParent(err)
			}
			if isMatch {
				return nil
			}
		}
	}
	return oidc.ErrInvalidRequestRedirectURI().
		WithDescription("The requested redirect_uri is missing in the client configuration. " +
			"If you have any questions, you may contact the administrator of the application.")
}

// ValidateAuthReqRedirectURI validates the passed redirect_uri and response_type to the registered uris and client type
func ValidateAuthReqRedirectURI(client Client, uri string, responseType oidc.ResponseType) error {
	if uri == "" {
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("The redirect_uri is missing in the request. " +
			"Please ensure it is added to the request. If you have any questions, you may contact the administrator of the application.")
	}
	if client.ApplicationType() == ApplicationTypeNative {
		return validateAuthReqRedirectURINative(client, uri)
	}
	if strings.HasPrefix(uri, "https://") {
		return checkURIAgainstRedirects(client, uri)
	}
	if err := checkURIAgainstRedirects(client, uri); err != nil {
		return err
	}
	if strings.HasPrefix(uri, "http://") {
		if client.DevMode() {
			return nil
		}
		if responseType == oidc.ResponseTypeCode && IsConfidentialType(client) {
			return nil
		}
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("This client's redirect_uri is http and is not allowed. " +
			"If you have any questions, you may contact the administrator of the application.")
	}
	return oidc.ErrInvalidRequestRedirectURI().WithDescription("This client's redirect_uri is using a custom schema and is not allowed. " +
		"If you have any questions, you may contact the administrator of the application.")
}

// ValidateAuthReqRedirectURINative validates the passed redirect_uri and response_type to the registered uris and client type
func validateAuthReqRedirectURINative(client Client, uri string) error {
	parsedURL, isLoopback := HTTPLoopbackOrLocalhost(uri)
	isCustomSchema := !(strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://"))
	if err := checkURIAgainstRedirects(client, uri); err == nil {
		if client.DevMode() {
			return nil
		}
		if !isLoopback && strings.HasPrefix(uri, "https://") {
			return nil
		}
		// The RedirectURIs are only valid for native clients when localhost or non-"http://" and "https://"
		if isLoopback || isCustomSchema {
			return nil
		}
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("This client's redirect_uri is http and is not allowed. " +
			"If you have any questions, you may contact the administrator of the application.")
	}
	if !isLoopback {
		return oidc.ErrInvalidRequestRedirectURI().WithDescription("The requested redirect_uri is missing in the client configuration. " +
			"If you have any questions, you may contact the administrator of the application.")
	}
	for _, uri := range client.RedirectURIs() {
		redirectURI, ok := HTTPLoopbackOrLocalhost(uri)
		if ok && equalURI(parsedURL, redirectURI) {
			return nil
		}
	}
	return oidc.ErrInvalidRequestRedirectURI().WithDescription("The requested redirect_uri is missing in the client configuration." +
		" If you have any questions, you may contact the administrator of the application.")
}

func equalURI(url1, url2 *url.URL) bool {
	return url1.Path == url2.Path && url1.RawQuery == url2.RawQuery
}

func HTTPLoopbackOrLocalhost(rawURL string) (*url.URL, bool) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
		hostName := parsedURL.Hostname()
		return parsedURL, hostName == "localhost" || net.ParseIP(hostName).IsLoopback()
	}
	return nil, false
}

// ValidateAuthReqResponseType validates the passed response_type to the registered response types
func ValidateAuthReqResponseType(client Client, responseType oidc.ResponseType) error {
	if responseType == "" {
		return oidc.ErrInvalidRequest().WithDescription("The response type is missing in your request. " +
			"If you have any questions, you may contact the administrator of the application.")
	}
	if !ContainsResponseType(client.ResponseTypes(), responseType) {
		return oidc.ErrUnauthorizedClient().WithDescription("The requested response type is missing in the client configuration. " +
			"If you have any questions, you may contact the administrator of the application.")
	}
	return nil
}

// ValidateAuthReqIDTokenHint validates the id_token_hint (if passed as parameter in the request)
// and returns the `sub` claim
func ValidateAuthReqIDTokenHint(ctx context.Context, idTokenHint string, verifier *IDTokenHintVerifier) (string, error) {
	if idTokenHint == "" {
		return "", nil
	}
	claims, err := VerifyIDTokenHint[*oidc.TokenClaims](ctx, idTokenHint, verifier)
	if err != nil && !errors.As(err, &IDTokenHintExpiredError{}) {
		return "", oidc.ErrLoginRequired().WithDescription("The id_token_hint is invalid. " +
			"If you have any questions, you may contact the administrator of the application.").WithParent(err)
	}
	return claims.GetSubject(), nil
}

// RedirectToLogin redirects the end user to the Login UI for authentication
func RedirectToLogin(authReqID string, client Client, w http.ResponseWriter, r *http.Request) {
	login := client.LoginURL(authReqID)
	http.Redirect(w, r, login, http.StatusFound)
}

// AuthorizeCallback handles the callback after authentication in the Login UI
func AuthorizeCallback(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	ctx, span := tracer.Start(r.Context(), "AuthorizeCallback")
	r = r.WithContext(ctx)
	defer span.End()

	id, err := ParseAuthorizeCallbackRequest(r)
	if err != nil {
		AuthRequestError(w, r, nil, err, authorizer)
		return
	}
	authReq, err := authorizer.Storage().AuthRequestByID(r.Context(), id)
	if err != nil {
		AuthRequestError(w, r, nil, err, authorizer)
		return
	}
	if !authReq.Done() {
		AuthRequestError(w, r, authReq,
			oidc.ErrInteractionRequired().WithDescription("Unfortunately, the user may be not logged in and/or additional interaction is required."),
			authorizer)
		return
	}
	AuthResponse(authReq, authorizer, w, r)
}

func ParseAuthorizeCallbackRequest(r *http.Request) (id string, err error) {
	if err = r.ParseForm(); err != nil {
		return "", fmt.Errorf("cannot parse form: %w", err)
	}
	id = r.Form.Get("id")
	if id == "" {
		return "", errors.New("auth request callback is missing id")
	}
	return id, nil
}

// AuthResponse creates the successful authentication response (either code or tokens)
func AuthResponse(authReq AuthRequest, authorizer Authorizer, w http.ResponseWriter, r *http.Request) {
	ctx, span := tracer.Start(r.Context(), "AuthResponse")
	r = r.WithContext(ctx)
	defer span.End()

	client, err := authorizer.Storage().GetClientByClientID(r.Context(), authReq.GetClientID())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer)
		return
	}
	if authReq.GetResponseType() == oidc.ResponseTypeCode {
		AuthResponseCode(w, r, authReq, authorizer)
		return
	}
	AuthResponseToken(w, r, authReq, authorizer, client)
}

// AuthResponseCode handles the creation of a successful authentication response using an authorization code
func AuthResponseCode(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer) {
	ctx, span := tracer.Start(r.Context(), "AuthResponseCode")
	defer span.End()
	r = r.WithContext(ctx)

	var err error
	if authReq.GetResponseMode() == oidc.ResponseModeFormPost {
		err = handleFormPostResponse(w, r, authReq, authorizer)
	} else {
		err = handleRedirectResponse(w, r, authReq, authorizer)
	}

	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer)
	}
}

// handleFormPostResponse processes the authentication response using form post method
func handleFormPostResponse(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer) error {
	codeResponse, err := BuildAuthResponseCodeResponsePayload(r.Context(), authReq, authorizer)
	if err != nil {
		return err
	}
	return AuthResponseFormPost(w, authReq.GetRedirectURI(), codeResponse, authorizer.Encoder())
}

// handleRedirectResponse processes the authentication response using the redirect method
func handleRedirectResponse(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer) error {
	callbackURL, err := BuildAuthResponseCallbackURL(r.Context(), authReq, authorizer)
	if err != nil {
		return err
	}
	http.Redirect(w, r, callbackURL, http.StatusFound)
	return nil
}

// BuildAuthResponseCodeResponsePayload generates the authorization code response payload for the authentication request
func BuildAuthResponseCodeResponsePayload(ctx context.Context, authReq AuthRequest, authorizer Authorizer) (*CodeResponseType, error) {
	code, err := CreateAuthRequestCode(ctx, authReq, authorizer.Storage(), authorizer.Crypto())
	if err != nil {
		return nil, err
	}

	sessionState := ""
	if authRequestSessionState, ok := authReq.(AuthRequestSessionState); ok {
		sessionState = authRequestSessionState.GetSessionState()
	}

	return &CodeResponseType{
		Code:         code,
		State:        authReq.GetState(),
		SessionState: sessionState,
	}, nil
}

// BuildAuthResponseCallbackURL generates the callback URL for a successful authorization code response
func BuildAuthResponseCallbackURL(ctx context.Context, authReq AuthRequest, authorizer Authorizer) (string, error) {
	codeResponse, err := BuildAuthResponseCodeResponsePayload(ctx, authReq, authorizer)
	if err != nil {
		return "", err
	}

	return AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), authReq.GetResponseMode(), codeResponse, authorizer.Encoder())
}

// AuthResponseToken creates the successful token(s) authentication response
func AuthResponseToken(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer, client Client) {
	ctx, span := tracer.Start(r.Context(), "AuthResponseToken")
	defer span.End()
	r = r.WithContext(ctx)

	createAccessToken := authReq.GetResponseType() != oidc.ResponseTypeIDTokenOnly
	resp, err := CreateTokenResponse(r.Context(), authReq, client, authorizer, createAccessToken, "", "")
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer)
		return
	}

	if authReq.GetResponseMode() == oidc.ResponseModeFormPost {
		err := AuthResponseFormPost(w, authReq.GetRedirectURI(), resp, authorizer.Encoder())
		if err != nil {
			AuthRequestError(w, r, authReq, err, authorizer)
			return
		}

		return
	}

	callback, err := AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), authReq.GetResponseMode(), resp, authorizer.Encoder())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer)
		return
	}
	http.Redirect(w, r, callback, http.StatusFound)
}

// CreateAuthRequestCode creates and stores a code for the auth code response
func CreateAuthRequestCode(ctx context.Context, authReq AuthRequest, storage Storage, crypto Crypto) (string, error) {
	ctx, span := tracer.Start(ctx, "CreateAuthRequestCode")
	defer span.End()

	code, err := BuildAuthRequestCode(authReq, crypto)
	if err != nil {
		return "", err
	}
	if err := storage.SaveAuthCode(ctx, authReq.GetID(), code); err != nil {
		return "", err
	}
	return code, nil
}

// BuildAuthRequestCode builds the string representation of the auth code
func BuildAuthRequestCode(authReq AuthRequest, crypto Crypto) (string, error) {
	return crypto.Encrypt(authReq.GetID())
}

// AuthResponseURL encodes the authorization response (successful and error) and sets it as query or fragment values
// depending on the response_mode and response_type
func AuthResponseURL(redirectURI string, responseType oidc.ResponseType, responseMode oidc.ResponseMode, response any, encoder httphelper.Encoder) (string, error) {
	uri, err := url.Parse(redirectURI)
	if err != nil {
		return "", oidc.ErrServerError().WithParent(err)
	}
	params, err := httphelper.URLEncodeParams(response, encoder)
	if err != nil {
		return "", oidc.ErrServerError().WithParent(err)
	}
	// return explicitly requested mode
	if responseMode == oidc.ResponseModeQuery {
		return mergeQueryParams(uri, params), nil
	}
	if responseMode == oidc.ResponseModeFragment {
		return setFragment(uri, params), nil
	}
	// implicit must use fragment mode is not specified by client
	if responseType == oidc.ResponseTypeIDToken || responseType == oidc.ResponseTypeIDTokenOnly {
		return setFragment(uri, params), nil
	}
	// if we get here it's code flow: defaults to query
	return mergeQueryParams(uri, params), nil
}

//go:embed form_post.html.tmpl
var formPostHtmlTemplate string

var formPostTmpl = template.Must(template.New("form_post").Parse(formPostHtmlTemplate))

// AuthResponseFormPost responds a html page that automatically submits the form which contains the auth response parameters
func AuthResponseFormPost(res http.ResponseWriter, redirectURI string, response any, encoder httphelper.Encoder) error {
	values := make(map[string][]string)
	err := encoder.Encode(response, values)
	if err != nil {
		return oidc.ErrServerError().WithParent(err)
	}

	params := &struct {
		RedirectURI string
		Params      any
	}{
		RedirectURI: redirectURI,
		Params:      values,
	}

	var buf bytes.Buffer
	err = formPostTmpl.Execute(&buf, params)
	if err != nil {
		return oidc.ErrServerError().WithParent(err)
	}

	res.Header().Set("Cache-Control", "no-store")
	res.WriteHeader(http.StatusOK)
	_, err = buf.WriteTo(res)
	if err != nil {
		return oidc.ErrServerError().WithParent(err)
	}

	return nil
}

func setFragment(uri *url.URL, params url.Values) string {
	uri.Fragment = params.Encode()
	return uri.String()
}

func mergeQueryParams(uri *url.URL, params url.Values) string {
	queries := uri.Query()
	for param, values := range params {
		for _, value := range values {
			queries.Add(param, value)
		}
	}
	uri.RawQuery = queries.Encode()
	return uri.String()
}
