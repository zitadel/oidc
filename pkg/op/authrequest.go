package op

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/rp"
	"github.com/caos/oidc/pkg/utils"
)

type Authorizer interface {
	Storage() Storage
	Decoder() utils.Decoder
	Encoder() utils.Encoder
	Signer() Signer
	IDTokenVerifier() rp.Verifier
	Crypto() Crypto
	Issuer() string
}

//AuthorizeValidator is an extension of Authorizer interface
//implementing it's own validation mechanism for the auth request
type AuthorizeValidator interface {
	Authorizer
	ValidateAuthRequest(context.Context, *oidc.AuthRequest, Storage, rp.Verifier) (string, error)
}

//ValidationAuthorizer  is an extension of Authorizer interface
//implementing it's own validation mechanism for the auth request
//
//Deprecated: ValidationAuthorizer exists for historical compatibility. Use ValidationAuthorizer itself
type ValidationAuthorizer AuthorizeValidator

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
	userID, err := validation(r.Context(), authReq, authorizer.Storage(), authorizer.IDTokenVerifier())
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

func ValidateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, storage Storage, verifier rp.Verifier) (string, error) {
	if err := ValidateAuthReqScopes(authReq.Scopes); err != nil {
		return "", err
	}
	if err := ValidateAuthReqRedirectURI(ctx, authReq.RedirectURI, authReq.ClientID, authReq.ResponseType, storage); err != nil {
		return "", err
	}
	if err := ValidateAuthReqResponseType(authReq.ResponseType); err != nil {
		return "", err
	}
	return ValidateAuthReqIDTokenHint(ctx, authReq.IDTokenHint, verifier)
}

func ValidateAuthReqScopes(scopes []string) error {
	if len(scopes) == 0 {
		return ErrInvalidRequest("Unfortunately, the scope parameter of your request is missing. Please ensure your scope value is not empty, and try again. If you have any questions, you may contact the administrator of the application.")
	}
	if !utils.Contains(scopes, oidc.ScopeOpenID) {
		return ErrInvalidRequest("Unfortunately, the scope `openid` is missing. Please ensure your scope configuration is correct (containing the `openid` value), and try again. If you have any questions, you may contact the administrator of the application.")
	}
	return nil
}

func ValidateAuthReqRedirectURI(ctx context.Context, uri, clientID string, responseType oidc.ResponseType, storage OPStorage) error {
	if uri == "" {
		return ErrInvalidRequestRedirectURI("Unfortunately, the client's redirect_uri is missing. Please ensure your redirect_uri is included in the request, and try again. If you have any questions, you may contact the administrator of the application.")
	}
	client, err := storage.GetClientByClientID(ctx, clientID)
	if err != nil {
		return ErrServerError(err.Error())
	}
	if !utils.Contains(client.RedirectURIs(), uri) {
		return ErrInvalidRequestRedirectURI("Unfortunately, the redirect_uri is missing in the client configuration. Please ensure your redirect_uri is added in the client configuration, and try again. If you have any questions, you may contact the administrator of the application.")
	}
	if strings.HasPrefix(uri, "https://") {
		return nil
	}
	if responseType == oidc.ResponseTypeCode {
		if strings.HasPrefix(uri, "http://") && IsConfidentialType(client) {
			return nil
		}
		if client.ApplicationType() == ApplicationTypeNative {
			return nil
		}
		return ErrInvalidRequest("Unfortunately, this client's redirect_uri is http and is not allowed. If you have any questions, you may contact the administrator of the application.")
	} else {
		if client.ApplicationType() != ApplicationTypeNative {
			return ErrInvalidRequestRedirectURI("Unfortunately, http is only allowed for native applications. Please change your redirect uri configuration and try again. If you have any questions, you may contact the administrator of the application.")
		}
		if !(strings.HasPrefix(uri, "http://localhost:") || strings.HasPrefix(uri, "http://localhost/")) {
			return ErrInvalidRequestRedirectURI("Unfortunately, http is only allowed for localhost url. Please change your redirect uri configuration and try again. If you have any questions, you may contact the administrator of the application at:")
		}
	}
	return nil
}

func ValidateAuthReqResponseType(responseType oidc.ResponseType) error {
	switch responseType {
	case oidc.ResponseTypeCode,
		oidc.ResponseTypeIDToken,
		oidc.ResponseTypeIDTokenOnly:
		return nil
	case "":
		return ErrInvalidRequest("Unfortunately, the response type is missing in your request. Please ensure the response type is complete and accurate, and try again. If you have any questions, you may contact the administrator of the application.")
	default:
		return ErrInvalidRequest("Unfortunately, the response type provided in your request is invalid. Please ensure the response type is valid, and try again. If you have any questions, you may contact the administrator of the application.")
	}
}

func ValidateAuthReqIDTokenHint(ctx context.Context, idTokenHint string, verifier rp.Verifier) (string, error) {
	if idTokenHint == "" {
		return "", nil
	}
	claims, err := verifier.VerifyIdToken(ctx, idTokenHint)
	if err != nil {
		return "", ErrInvalidRequest("Unfortunately, the id_token_hint is invalid. Please ensure the id_token_hint is complete and accurate, and try again. If you have any questions, you may contact the administrator of the application.")
	}
	return claims.Subject, nil
}

func RedirectToLogin(authReqID string, client Client, w http.ResponseWriter, r *http.Request) {
	login := client.LoginURL(authReqID)
	http.Redirect(w, r, login, http.StatusFound)
}

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

func AuthResponse(authReq AuthRequest, authorizer Authorizer, w http.ResponseWriter, r *http.Request) {
	client, err := authorizer.Storage().GetClientByClientID(r.Context(), authReq.GetClientID())
	if err != nil {

	}
	if authReq.GetResponseType() == oidc.ResponseTypeCode {
		AuthResponseCode(w, r, authReq, authorizer)
		return
	}
	AuthResponseToken(w, r, authReq, authorizer, client)
	return
}

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
