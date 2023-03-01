package op

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"github.com/gorilla/mux"

	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
	str "github.com/zitadel/oidc/pkg/strings"
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

type Authorizer interface {
	Storage() Storage
	Decoder() httphelper.Decoder
	Encoder() httphelper.Encoder
	Signer() Signer
	IDTokenHintVerifier() IDTokenHintVerifier
	Crypto() Crypto
	Issuer() string
	RequestObjectSupported() bool
}

// AuthorizeValidator is an extension of Authorizer interface
// implementing its own validation mechanism for the auth request
type AuthorizeValidator interface {
	Authorizer
	ValidateAuthRequest(context.Context, *oidc.AuthRequest, Storage, IDTokenHintVerifier) (string, error)
}

func authorizeHandler(authorizer Authorizer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Authorize(w, r, authorizer)
	}
}

func authorizeCallbackHandler(authorizer Authorizer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		AuthorizeCallback(w, r, authorizer)
	}
}

// Authorize handles the authorization request, including
// parsing, validating, storing and finally redirecting to the login handler
func Authorize(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	authReq, err := ParseAuthorizeRequest(r, authorizer.Decoder())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	if authReq.RequestParam != "" && authorizer.RequestObjectSupported() {
		authReq, err = ParseRequestObject(r.Context(), authReq, authorizer.Storage(), authorizer.Issuer())
		if err != nil {
			AuthRequestError(w, r, authReq, err, authorizer.Encoder())
			return
		}
	}
	if authReq.ClientID == "" {
		AuthRequestError(w, r, authReq, fmt.Errorf("auth request is missing client_id"), authorizer.Encoder())
		return
	}
	if authReq.RedirectURI == "" {
		AuthRequestError(w, r, authReq, fmt.Errorf("auth request is missing redirect_uri"), authorizer.Encoder())
		return
	}
	validation := ValidateAuthRequest
	if validater, ok := authorizer.(AuthorizeValidator); ok {
		validation = validater.ValidateAuthRequest
	}
	userID, err := validation(r.Context(), authReq, authorizer.Storage(), authorizer.IDTokenHintVerifier())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	if authReq.RequestParam != "" {
		AuthRequestError(w, r, authReq, oidc.ErrRequestNotSupported(), authorizer.Encoder())
		return
	}
	req, err := authorizer.Storage().CreateAuthRequest(r.Context(), authReq, userID)
	if err != nil {
		AuthRequestError(w, r, authReq, oidc.DefaultToServerError(err, "unable to save auth request"), authorizer.Encoder())
		return
	}
	client, err := authorizer.Storage().GetClientByClientID(r.Context(), req.GetClientID())
	if err != nil {
		AuthRequestError(w, r, req, oidc.DefaultToServerError(err, "unable to retrieve client by id"), authorizer.Encoder())
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
func ParseRequestObject(ctx context.Context, authReq *oidc.AuthRequest, storage Storage, issuer string) (*oidc.AuthRequest, error) {
	requestObject := new(oidc.RequestObject)
	payload, err := oidc.ParseToken(authReq.RequestParam, requestObject)
	if err != nil {
		return nil, err
	}

	if requestObject.ClientID != "" && requestObject.ClientID != authReq.ClientID {
		return authReq, oidc.ErrInvalidRequest()
	}
	if requestObject.ResponseType != "" && requestObject.ResponseType != authReq.ResponseType {
		return authReq, oidc.ErrInvalidRequest()
	}
	if requestObject.Issuer != requestObject.ClientID {
		return authReq, oidc.ErrInvalidRequest()
	}
	if !str.Contains(requestObject.Audience, issuer) {
		return authReq, oidc.ErrInvalidRequest()
	}
	keySet := &jwtProfileKeySet{storage: storage, clientID: requestObject.Issuer}
	if err = oidc.CheckSignature(ctx, authReq.RequestParam, payload, requestObject, nil, keySet); err != nil {
		return authReq, err
	}
	CopyRequestObjectToAuthRequest(authReq, requestObject)
	return authReq, nil
}

// CopyRequestObjectToAuthRequest overwrites present values from the Request Object into the auth request
// and clears the `RequestParam` of the auth request
func CopyRequestObjectToAuthRequest(authReq *oidc.AuthRequest, requestObject *oidc.RequestObject) {
	if str.Contains(authReq.Scopes, oidc.ScopeOpenID) && len(requestObject.Scopes) > 0 {
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

// ValidateAuthRequest validates the authorize parameters and returns the userID of the id_token_hint if passed
func ValidateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, storage Storage, verifier IDTokenHintVerifier) (sub string, err error) {
	authReq.MaxAge, err = ValidateAuthReqPrompt(authReq.Prompt, authReq.MaxAge)
	if err != nil {
		return "", err
	}
	client, err := storage.GetClientByClientID(ctx, authReq.ClientID)
	if err != nil {
		return "", oidc.DefaultToServerError(err, "unable to retrieve client by id")
	}
	authReq.Scopes, err = ValidateAuthReqScopes(client, authReq.Scopes)
	if err != nil {
		return "", err
	}
	if err := ValidateAuthReqRedirectURI(client, authReq.RedirectURI, authReq.ResponseType); err != nil {
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

// ValidateAuthReqScopes validates the passed scopes
func ValidateAuthReqScopes(client Client, scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, oidc.ErrInvalidRequest().
			WithDescription("The scope of your request is missing. Please ensure some scopes are requested. " +
				"If you have any questions, you may contact the administrator of the application.")
	}
	openID := false
	for i := len(scopes) - 1; i >= 0; i-- {
		scope := scopes[i]
		if scope == oidc.ScopeOpenID {
			openID = true
			continue
		}
		if !(scope == oidc.ScopeProfile ||
			scope == oidc.ScopeEmail ||
			scope == oidc.ScopePhone ||
			scope == oidc.ScopeAddress ||
			scope == oidc.ScopeOfflineAccess) &&
			!client.IsScopeAllowed(scope) {
			scopes[i] = scopes[len(scopes)-1]
			scopes[len(scopes)-1] = ""
			scopes = scopes[:len(scopes)-1]
		}
	}
	if !openID {
		return nil, oidc.ErrInvalidScope().WithDescription("The scope openid is missing in your request. " +
			"Please ensure the scope openid is added to the request. " +
			"If you have any questions, you may contact the administrator of the application.")
	}

	return scopes, nil
}

// checkURIAginstRedirects just checks aginst the valid redirect URIs and ignores
// other factors.
func checkURIAginstRedirects(client Client, uri string) error {
	if str.Contains(client.RedirectURIs(), uri) {
		return nil
	}
	if globClient, ok := client.(HasRedirectGlobs); ok {
		for _, uriGlob := range globClient.RedirectURIGlobs() {
			matcher, err := glob.Compile(uriGlob)
			if err != nil {
				return oidc.ErrServerError().WithParent(err)
			}
			if matcher.Match(uri) {
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
	if strings.HasPrefix(uri, "https://") {
		return checkURIAginstRedirects(client, uri)
	}
	if client.ApplicationType() == ApplicationTypeNative {
		return validateAuthReqRedirectURINative(client, uri, responseType)
	}
	if err := checkURIAginstRedirects(client, uri); err != nil {
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
func validateAuthReqRedirectURINative(client Client, uri string, responseType oidc.ResponseType) error {
	parsedURL, isLoopback := HTTPLoopbackOrLocalhost(uri)
	isCustomSchema := !strings.HasPrefix(uri, "http://")
	if err := checkURIAginstRedirects(client, uri); err == nil {
		if client.DevMode() {
			return nil
		}
		// The RedirectURIs are only valid for native clients when localhost or non-"http://"
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

func HTTPLoopbackOrLocalhost(rawurl string) (*url.URL, bool) {
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		return nil, false
	}
	if parsedURL.Scheme != "http" {
		return nil, false
	}
	hostName := parsedURL.Hostname()
	return parsedURL, hostName == "localhost" || net.ParseIP(hostName).IsLoopback()
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
func ValidateAuthReqIDTokenHint(ctx context.Context, idTokenHint string, verifier IDTokenHintVerifier) (string, error) {
	if idTokenHint == "" {
		return "", nil
	}
	claims, err := VerifyIDTokenHint(ctx, idTokenHint, verifier)
	if err != nil {
		return "", oidc.ErrLoginRequired().WithDescription("The id_token_hint is invalid. " +
			"If you have any questions, you may contact the administrator of the application.")
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
	params := mux.Vars(r)
	id := params["id"]
	if id == "" {
		AuthRequestError(w, r, nil, fmt.Errorf("auth request callback is missing id"), authorizer.Encoder())
		return
	}

	authReq, err := authorizer.Storage().AuthRequestByID(r.Context(), id)
	if err != nil {
		AuthRequestError(w, r, nil, err, authorizer.Encoder())
		return
	}
	if !authReq.Done() {
		AuthRequestError(w, r, authReq,
			oidc.ErrInteractionRequired().WithDescription("Unfortunately, the user may be not logged in and/or additional interaction is required."),
			authorizer.Encoder())
		return
	}
	AuthResponse(authReq, authorizer, w, r)
}

// AuthResponse creates the successful authentication response (either code or tokens)
func AuthResponse(authReq AuthRequest, authorizer Authorizer, w http.ResponseWriter, r *http.Request) {
	client, err := authorizer.Storage().GetClientByClientID(r.Context(), authReq.GetClientID())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	if authReq.GetResponseType() == oidc.ResponseTypeCode {
		AuthResponseCode(w, r, authReq, authorizer)
		return
	}
	AuthResponseToken(w, r, authReq, authorizer, client)
}

// AuthResponseCode creates the successful code authentication response
func AuthResponseCode(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer) {
	code, err := CreateAuthRequestCode(r.Context(), authReq, authorizer.Storage(), authorizer.Crypto())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	codeResponse := struct {
		code  string
		state string
	}{
		code:  code,
		state: authReq.GetState(),
	}
	callback, err := AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), authReq.GetResponseMode(), &codeResponse, authorizer.Encoder())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	http.Redirect(w, r, callback, http.StatusFound)
}

// AuthResponseToken creates the successful token(s) authentication response
func AuthResponseToken(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer, client Client) {
	createAccessToken := authReq.GetResponseType() != oidc.ResponseTypeIDTokenOnly
	resp, err := CreateTokenResponse(r.Context(), authReq, client, authorizer, createAccessToken, "", "")
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	callback, err := AuthResponseURL(authReq.GetRedirectURI(), authReq.GetResponseType(), authReq.GetResponseMode(), resp, authorizer.Encoder())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	http.Redirect(w, r, callback, http.StatusFound)
}

// CreateAuthRequestCode creates and stores a code for the auth code response
func CreateAuthRequestCode(ctx context.Context, authReq AuthRequest, storage Storage, crypto Crypto) (string, error) {
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
func AuthResponseURL(redirectURI string, responseType oidc.ResponseType, responseMode oidc.ResponseMode, response interface{}, encoder httphelper.Encoder) (string, error) {
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
