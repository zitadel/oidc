package op

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

type Authorizer interface {
	Storage() Storage
	Decoder() *schema.Decoder
	Encoder() *schema.Encoder
	Signer() Signer
	Issuer() string
	// ErrorHandler() func(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error)
}

// type Signer interface {
// 	Sign(claims *oidc.IDTokenClaims) (string, error)
// }

type ValidationAuthorizer interface {
	Authorizer
	ValidateAuthRequest(*oidc.AuthRequest, Storage) error
}

// type errorHandler func(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error)
// type callbackHandler func(authReq *oidc.AuthRequest, client oidc.Client, w http.ResponseWriter, r *http.Request)

func Authorize(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	err := r.ParseForm()
	if err != nil {
		AuthRequestError(w, r, nil, ErrInvalidRequest("cannot parse form"), authorizer.Encoder())
		// AuthRequestError(w, r, nil, )
		return
	}
	authReq := new(oidc.AuthRequest)

	err = authorizer.Decoder().Decode(authReq, r.Form)
	if err != nil {
		AuthRequestError(w, r, nil, ErrInvalidRequest(fmt.Sprintf("cannot parse auth request: %v", err)), authorizer.Encoder())
		return
	}

	validation := ValidateAuthRequest
	if validater, ok := authorizer.(ValidationAuthorizer); ok {
		validation = validater.ValidateAuthRequest
	}
	if err := validation(authReq, authorizer.Storage()); err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}

	req, err := authorizer.Storage().CreateAuthRequest(authReq)
	if err != nil {
		AuthRequestError(w, r, authReq, err, authorizer.Encoder())
		return
	}

	client, err := authorizer.Storage().GetClientByClientID(req.GetClientID())
	if err != nil {
		AuthRequestError(w, r, req, err, authorizer.Encoder())
		return
	}
	RedirectToLogin(req.GetID(), client, w, r)
}

func ValidateAuthRequest(authReq *oidc.AuthRequest, storage Storage) error {
	if err := ValidateAuthReqScopes(authReq.Scopes); err != nil {
		return err
	}
	if err := ValidateAuthReqRedirectURI(authReq.RedirectURI, authReq.ClientID, authReq.ResponseType, storage); err != nil {
		return err
	}
	return nil
	// return errors.New("Unimplemented") //TODO: impl https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.2

	// if NeedsExistingSession(authRequest) {
	// 	session, err := storage.CheckSession(authRequest)
	// 	if err != nil {
	// 		//TODO: return err<
	// 	}
	// }
}

func ValidateAuthReqScopes(scopes []string) error {
	if len(scopes) == 0 {
		return ErrInvalidRequest("scope missing")
	}
	if !utils.Contains(scopes, oidc.ScopeOpenID) {
		return ErrInvalidRequest("scope openid missing")
	}
	return nil
}

func ValidateAuthReqRedirectURI(uri, client_id string, responseType oidc.ResponseType, storage OPStorage) error {
	if uri == "" {
		return ErrInvalidRequest("redirect_uri must not be empty")
	}
	client, err := storage.GetClientByClientID(client_id)
	if err != nil {
		return ErrServerError(err.Error())
	}
	if !utils.Contains(client.RedirectURIs(), uri) {
		return ErrInvalidRequest("redirect_uri not allowed")
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
		return ErrInvalidRequest("redirect_uri not allowed 2")
	} else {
		if client.ApplicationType() != ApplicationTypeNative {
			return ErrInvalidRequest("redirect_uri not allowed 3")
		}
		if !(strings.HasPrefix(uri, "http://localhost:") || strings.HasPrefix(uri, "http://localhost/")) {
			return ErrInvalidRequest("redirect_uri not allowed 4")
		}
	}
	return nil
}

func RedirectToLogin(authReqID string, client Client, w http.ResponseWriter, r *http.Request) {
	login := client.LoginURL(authReqID)
	http.Redirect(w, r, login, http.StatusFound)
}

func AuthorizeCallback(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	params := mux.Vars(r)
	id := params["id"]

	authReq, err := authorizer.Storage().AuthRequestByID(id)
	if err != nil {
		AuthRequestError(w, r, nil, err, authorizer.Encoder())
		return
	}
	AuthResponse(authReq, authorizer, w, r)
}

func AuthResponse(authReq AuthRequest, authorizer Authorizer, w http.ResponseWriter, r *http.Request) {
	var callback string
	if authReq.GetResponseType() == oidc.ResponseTypeCode {
		callback = fmt.Sprintf("%s?code=%s", authReq.GetRedirectURI(), authReq.GetCode())
	} else {
		var accessToken string
		var err error
		var exp uint64
		if authReq.GetResponseType() != oidc.ResponseTypeIDTokenOnly {
			accessToken, exp, err = CreateAccessToken(authReq, authorizer.Signer())
			if err != nil {

			}
		}
		idToken, err := CreateIDToken(authorizer.Issuer(), authReq, time.Duration(0), accessToken, "", authorizer.Signer())
		if err != nil {

		}
		resp := &oidc.AccessTokenResponse{
			AccessToken: accessToken,
			IDToken:     idToken,
			TokenType:   oidc.BearerToken,
			ExpiresIn:   exp,
		}
		params, err := utils.URLEncodeResponse(resp, authorizer.Encoder())
		if err != nil {

		}
		callback = fmt.Sprintf("%s#%s", authReq.GetRedirectURI(), params)
	}
	http.Redirect(w, r, callback, http.StatusFound)
}
