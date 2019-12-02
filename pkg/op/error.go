package op

import (
	"net/http"
	"net/url"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

const (
	InvalidRequest errorType = "invalid_request"
	ServerError    errorType = "server_error"
)

type errorType string

type ErrAuthRequest interface {
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetState() string
}

func AuthRequestError(w http.ResponseWriter, r *http.Request, authReq ErrAuthRequest, err error) {
	if authReq == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if authReq.GetRedirectURI() == "" {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	url := authReq.GetRedirectURI()
	if authReq.GetResponseType() == oidc.ResponseTypeCode {
		url += "?"
	} else {
		url += "#"
	}
	var errorType errorType
	var description string
	if e, ok := err.(*OAuthError); ok {
		errorType = e.ErrorType
		description = e.Description
	} else {
		errorType = ServerError
		description = err.Error()
	}
	url += "error=" + string(errorType)
	if description != "" {
		url += "&error_description=" + description
	}
	if authReq.GetState() != "" {
		url += "&state=" + authReq.GetState()
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func ExchangeRequestError(w http.ResponseWriter, r *http.Request, err error) {
	e, ok := err.(*OAuthError)
	if !ok {
		e.ErrorType = ServerError
		e.Description = err.Error()
	}
	utils.MarshalJSON(w, e)
}

type OAuthError struct {
	ErrorType   errorType `json:"error"`
	Description string    `json:"description"`
}

var (
	ErrInvalidRequest = func(description string, args ...interface{}) *OAuthError {
		return &OAuthError{
			ErrorType:   InvalidRequest,
			Description: description,
		}
	}
	ErrServerError = func(description string, args ...interface{}) *OAuthError {
		return &OAuthError{
			ErrorType:   ServerError,
			Description: description,
		}
	}
)

func (e *OAuthError) AuthRequestResponse(w http.ResponseWriter, r *http.Request, authReq AuthRequest) {
	if authReq == nil {
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}
	if authReq.GetRedirectURI() == "" {
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}
	callback := authReq.GetRedirectURI()
	if authReq.GetResponseType() == oidc.ResponseTypeCode {
		callback += "?"
	} else {
		callback += "#"
	}
	callback += "error=" + string(e.ErrorType)
	if e.Description != "" {
		callback += "&error_description=" + url.QueryEscape(e.Description)
	}
	if authReq.GetState() != "" {
		callback += "&state=" + authReq.GetState()
	}
	http.Redirect(w, r, callback, http.StatusFound)
}

func (e *OAuthError) Error() string {
	return ""
}
