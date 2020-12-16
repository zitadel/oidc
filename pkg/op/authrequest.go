package op

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type Authorizer interface {
	Storage() Storage
	Decoder() utils.Decoder
	Encoder() utils.Encoder
	Signer() Signer
	IDTokenHintVerifier() IDTokenHintVerifier
	Crypto() Crypto
	Issuer() string
}

//AuthorizeValidator is an extension of Authorizer interface
//implementing it's own validation mechanism for the auth request
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

//Authorize handles the authorization request, including
//parsing, validating, storing and finally redirecting to the login handler
func Authorize(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	authReq, err := ParseAuthorizeRequest(r, authorizer.Decoder())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
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
	req, err := authorizer.Storage().CreateAuthRequest(r.Context(), authReq, userID)
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	client, err := authorizer.Storage().GetClientByClientID(r.Context(), req.GetClientID())
	if err != nil {
		AuthRequestError(w, r, req, err, authorizer.Encoder())
		return
	}
	RedirectToLogin(req.GetID(), client, w, r)
}

//ParseAuthorizeRequest parsed the http request into a AuthRequest
func ParseAuthorizeRequest(r *http.Request, decoder utils.Decoder) (*oidc.AuthRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, ErrInvalidRequest("cannot parse form")
	}
	authReq := new(oidc.AuthRequest)
	err = decoder.Decode(authReq, r.Form)
	if err != nil {
		return nil, ErrInvalidRequest(fmt.Sprintf("cannot parse auth request: %v", err))
	}
	return authReq, nil
}

//ValidateAuthRequest validates the authorize parameters and returns the userID of the id_token_hint if passed
func ValidateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, storage Storage, verifier IDTokenHintVerifier) (string, error) {
	client, err := storage.GetClientByClientID(ctx, authReq.ClientID)
	if err != nil {
		return "", ErrServerError(err.Error())
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

//ValidateAuthReqScopes validates the passed scopes
func ValidateAuthReqScopes(client Client, scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, ErrInvalidRequest("The scope of your request is missing. Please ensure some scopes are requested. If you have any questions, you may contact the administrator of the application.")
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
		return nil, ErrInvalidRequest("The scope openid is missing in your request. Please ensure the scope openid is added to the request. If you have any questions, you may contact the administrator of the application.")
	}

	return scopes, nil
}

//ValidateAuthReqRedirectURI validates the passed redirect_uri and response_type to the registered uris and client type
func ValidateAuthReqRedirectURI(client Client, uri string, responseType oidc.ResponseType) error {
	if uri == "" {
		return ErrInvalidRequestRedirectURI("The redirect_uri is missing in the request. Please ensure it is added to the request. If you have any questions, you may contact the administrator of the application.")
	}
	if !utils.Contains(client.RedirectURIs(), uri) {
		return ErrInvalidRequestRedirectURI("The requested redirect_uri is missing in the client configuration. If you have any questions, you may contact the administrator of the application.")
	}
	if client.DevMode() {
		return nil
	}
	if strings.HasPrefix(uri, "https://") {
		return nil
	}
	if responseType == oidc.ResponseTypeCode {
		if strings.HasPrefix(uri, "http://") && IsConfidentialType(client) {
			return nil
		}
		if !strings.HasPrefix(uri, "http://") && client.ApplicationType() == ApplicationTypeNative {
			return nil
		}
		return ErrInvalidRequest("This client's redirect_uri is http and is not allowed. If you have any questions, you may contact the administrator of the application.")
	} else {
		if client.ApplicationType() != ApplicationTypeNative {
			return ErrInvalidRequestRedirectURI("Http is only allowed for native applications. Please change your redirect uri try again. If you have any questions, you may contact the administrator of the application.")
		}
		if !(strings.HasPrefix(uri, "http://localhost:") || strings.HasPrefix(uri, "http://localhost/")) {
			return ErrInvalidRequestRedirectURI("Http is only allowed for localhost uri. Please change your redirect uri try again. If you have any questions, you may contact the administrator of the application at:")
		}
	}
	return nil
}

//ValidateAuthReqResponseType validates the passed response_type to the registered response types
func ValidateAuthReqResponseType(client Client, responseType oidc.ResponseType) error {
	if responseType == "" {
		return ErrInvalidRequest("The response type is missing in your request. If you have any questions, you may contact the administrator of the application.")
	}
	if !ContainsResponseType(client.ResponseTypes(), responseType) {
		return ErrInvalidRequest("The requested response type is missing in the client configuration. If you have any questions, you may contact the administrator of the application.")
	}
	return nil
}

//ValidateAuthReqIDTokenHint validates the id_token_hint (if passed as parameter in the request)
//and returns the `sub` claim
func ValidateAuthReqIDTokenHint(ctx context.Context, idTokenHint string, verifier IDTokenHintVerifier) (string, error) {
	if idTokenHint == "" {
		return "", nil
	}
	claims, err := VerifyIDTokenHint(ctx, idTokenHint, verifier)
	if err != nil {
		return "", ErrInvalidRequest("The id_token_hint is invalid. If you have any questions, you may contact the administrator of the application.")
	}
	return claims.GetSubject(), nil
}

//RedirectToLogin redirects the end user to the Login UI for authentication
func RedirectToLogin(authReqID string, client Client, w http.ResponseWriter, r *http.Request) {
	login := client.LoginURL(authReqID)
	http.Redirect(w, r, login, http.StatusFound)
}

//AuthorizeCallback handles the callback after authentication in the Login UI
func AuthorizeCallback(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	params := mux.Vars(r)
	id := params["id"]

	authReq, err := authorizer.Storage().AuthRequestByID(r.Context(), id)
	if err != nil {
		AuthRequestError(w, r, nil, err, authorizer.Encoder())
		return
	}
	if !authReq.Done() {
		AuthRequestError(w, r, authReq, ErrInteractionRequired("Unfortunately, the user may is not logged in and/or additional interaction is required."), authorizer.Encoder())
		return
	}
	AuthResponse(authReq, authorizer, w, r)
}

//AuthResponse creates the successful authentication response (either code or tokens)
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

//AuthResponseCode creates the successful code authentication response
func AuthResponseCode(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer) {
	code, err := CreateAuthRequestCode(r.Context(), authReq, authorizer.Storage(), authorizer.Crypto())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	callback := fmt.Sprintf("%s?code=%s", authReq.GetRedirectURI(), code)
	if authReq.GetState() != "" {
		callback = callback + "&state=" + authReq.GetState()
	}
	http.Redirect(w, r, callback, http.StatusFound)
}

//AuthResponseToken creates the successful token(s) authentication response
func AuthResponseToken(w http.ResponseWriter, r *http.Request, authReq AuthRequest, authorizer Authorizer, client Client) {
	createAccessToken := authReq.GetResponseType() != oidc.ResponseTypeIDTokenOnly
	resp, err := CreateTokenResponse(r.Context(), authReq, client, authorizer, createAccessToken, "")
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	params, err := utils.URLEncodeResponse(resp, authorizer.Encoder())
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}
	callback := fmt.Sprintf("%s#%s", authReq.GetRedirectURI(), params)
	http.Redirect(w, r, callback, http.StatusFound)
}

//CreateAuthRequestCode creates and stores a code for the auth code response
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

func BuildAuthRequestCode(authReq AuthRequest, crypto Crypto) (string, error) {
	return crypto.Encrypt(authReq.GetID())
}
