package op

import (
	"net/http"

	"github.com/caos/oidc/pkg/oidc"
)

const (
	InvalidRequest errorType = "invalid_request"
	ServerError    errorType = "server_error"
)

type errorType string

func AuthRequestError(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest, err error) {
	if authReq == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if authReq.RedirectURI == "" {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	url := authReq.RedirectURI
	if authReq.ResponseType == oidc.ResponseTypeCode {
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
	if authReq.State != "" {
		url += "&state=" + authReq.State
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func ExchangeRequestError(w http.ResponseWriter, r *http.Request, exchangeReq *oidc.AuthRequest, err error) {

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

func (e *OAuthError) AuthRequestResponse(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthRequest) {
	if authReq == nil {
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}
	if authReq.RedirectURI == "" {
		http.Error(w, e.Error(), http.StatusBadRequest)
		return
	}
	url := authReq.RedirectURI
	if authReq.ResponseType == oidc.ResponseTypeCode {
		url += "?"
	} else {
		url += "#"
	}
	url += "error=" + string(e.ErrorType)
	if e.Description != "" {
		url += "&error_description=" + e.Description
	}
	if authReq.State != "" {
		url += "&state=" + authReq.State
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (e *OAuthError) Error() string {
	return ""
}
