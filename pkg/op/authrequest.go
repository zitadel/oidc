package op

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op/u"
	str_utils "github.com/caos/utils/strings"
)

type Authorizer interface {
	Storage() u.Storage
	Decoder() *schema.Decoder
	Encoder() *schema.Encoder
	Signe() u.Signer
	ErrorHandler() func(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error)
}

// type Signer interface {
// 	Sign(claims *oidc.IDTokenClaims) (string, error)
// }

type ValidationAuthorizer interface {
	Authorizer
	ValidateAuthRequest(*oidc.AuthRequest, u.Storage) error
}

// type errorHandler func(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error)
type callbackHandler func(authReq *oidc.AuthRequest, client oidc.Client, w http.ResponseWriter, r *http.Request)

func Authorize(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	err := r.ParseForm()
	if err != nil {
		AuthRequestError(w, r, nil, ErrInvalidRequest("cannot parse form"))
		// AuthRequestError(w, r, nil, )
		return
	}
	authReq := new(oidc.AuthRequest)

	err = authorizer.Decoder().Decode(authReq, r.Form)
	if err != nil {
		AuthRequestError(w, r, nil, ErrInvalidRequest(fmt.Sprintf("cannot parse auth request: %v", err)))
		return
	}

	validation := ValidateAuthRequest
	if validater, ok := authorizer.(ValidationAuthorizer); ok {
		validation = validater.ValidateAuthRequest
	}
	if err := validation(authReq, authorizer.Storage()); err != nil {
		AuthRequestError(w, r, authReq, err)
		return
	}

	err = authorizer.Storage().CreateAuthRequest(authReq)
	if err != nil {
		AuthRequestError(w, r, authReq, err)
		return
	}

	client, err := authorizer.Storage().GetClientByClientID(authReq.ClientID)
	if err != nil {
		AuthRequestError(w, r, authReq, err)
		return
	}
	RedirectToLogin(authReq, client, w, r)
}

func ValidateAuthRequest(authReq *oidc.AuthRequest, storage u.Storage) error {
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
	if !str_utils.Contains(scopes, oidc.ScopeOpenID) {
		return ErrInvalidRequest("scope openid missing")
	}
	return nil
}

func ValidateAuthReqRedirectURI(uri, client_id string, responseType oidc.ResponseType, storage u.Storage) error {
	if uri == "" {
		return ErrInvalidRequest("redirect_uri must not be empty")
	}
	client, err := storage.GetClientByClientID(client_id)
	if err != nil {
		return ErrServerError(err.Error())
	}
	if !str_utils.Contains(client.RedirectURIs(), uri) {
		return ErrInvalidRequest("redirect_uri not allowed")
	}
	if strings.HasPrefix(uri, "https://") {
		return nil
	}
	if responseType == oidc.ResponseTypeCode {
		if strings.HasPrefix(uri, "http://") && oidc.IsConfidentialType(client) {
			return nil
		}
		if client.ApplicationType() == oidc.ApplicationTypeNative {
			return nil
		}
		return ErrInvalidRequest("redirect_uri not allowed 2")
	} else {
		if client.ApplicationType() != oidc.ApplicationTypeNative {
			return ErrInvalidRequest("redirect_uri not allowed 3")
		}
		if !(strings.HasPrefix(uri, "http://localhost:") || strings.HasPrefix(uri, "http://localhost/")) {
			return ErrInvalidRequest("redirect_uri not allowed 4")
		}
	}
	return nil
}

func RedirectToLogin(authReq *oidc.AuthRequest, client oidc.Client, w http.ResponseWriter, r *http.Request) {
	login := client.LoginURL(authReq.ID)
	http.Redirect(w, r, login, http.StatusFound)
}

func AuthorizeCallback(w http.ResponseWriter, r *http.Request, authorizer Authorizer) {
	params := mux.Vars(r)
	id := params["id"]

	authReq, err := authorizer.Storage().AuthRequestByID(id)
	if err != nil {
		AuthRequestError(w, r, nil, err)
		return
	}
	AuthResponse(authReq, authorizer, w, r)
}

func AuthResponse(authReq *oidc.AuthRequest, authorizer Authorizer, w http.ResponseWriter, r *http.Request) {
	var callback string
	if authReq.ResponseType == oidc.ResponseTypeCode {
		callback = fmt.Sprintf("%s?code=%s", authReq.RedirectURI, "test")
	} else {
		var accessToken string
		var err error
		if authReq.ResponseType != oidc.ResponseTypeIDTokenOnly {
			accessToken, err = CreateAccessToken()
			if err != nil {

			}
		}
		idToken, err := CreateIDToken(authReq, accessToken, authorizer.Signe())
		if err != nil {

		}
		resp := &oidc.AccessTokenResponse{
			AccessToken: accessToken,
			IDToken:     idToken,
			TokenType:   "Bearer",
		}
		values := make(map[string][]string)
		authorizer.Encoder().Encode(resp, values)
		v := url.Values(values)
		callback = fmt.Sprintf("%s#%s", authReq.RedirectURI, v.Encode())
	}
	http.Redirect(w, r, callback, http.StatusFound)
}
