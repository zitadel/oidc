package op

import (
	"fmt"
	"net/http"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

const (
	InvalidRequest      errorType = "invalid_request"
	InvalidRequestUri   errorType = "invalid_request_uri"
	InteractionRequired errorType = "interaction_required"
	ServerError         errorType = "server_error"
)

var (
	ErrInvalidRequest = func(description string) *OAuthError {
		return &OAuthError{
			ErrorType:   InvalidRequest,
			Description: description,
		}
	}
	ErrInvalidRequestRedirectURI = func(description string) *OAuthError {
		return &OAuthError{
			ErrorType:        InvalidRequestUri,
			Description:      description,
			redirectDisabled: true,
		}
	}
	ErrInteractionRequired = func(description string) *OAuthError {
		return &OAuthError{
			ErrorType:   InteractionRequired,
			Description: description,
		}
	}
	ErrServerError = func(description string) *OAuthError {
		return &OAuthError{
			ErrorType:   ServerError,
			Description: description,
		}
	}
)

type errorType string

type ErrAuthRequest interface {
	GetRedirectURI() string
	GetResponseType() oidc.ResponseType
	GetState() string
}

func AuthRequestError(w http.ResponseWriter, r *http.Request, authReq ErrAuthRequest, err error, encoder utils.Encoder) {
	if authReq == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e, ok := err.(*OAuthError)
	if !ok {
		e = new(OAuthError)
		e.ErrorType = ServerError
		e.Description = err.Error()
	}
	e.State = authReq.GetState()
	if authReq.GetRedirectURI() == "" || e.redirectDisabled {
		http.Error(w, e.Description, http.StatusBadRequest)
		return
	}
	params, err := utils.URLEncodeResponse(e, encoder)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	url := authReq.GetRedirectURI()
	responseType := authReq.GetResponseType()
	if responseType == "" || responseType == oidc.ResponseTypeCode {
		url += "?" + params
	} else {
		url += "#" + params
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func RequestError(w http.ResponseWriter, r *http.Request, err error) {
	e, ok := err.(*OAuthError)
	if !ok {
		e = new(OAuthError)
		e.ErrorType = ServerError
		e.Description = err.Error()
	}
	w.WriteHeader(http.StatusBadRequest)
	utils.MarshalJSON(w, e)
}

type OAuthError struct {
	ErrorType        errorType `json:"error" schema:"error"`
	Description      string    `json:"error_description,omitempty" schema:"error_description,omitempty"`
	State            string    `json:"state,omitempty" schema:"state,omitempty"`
	redirectDisabled bool      `json:"-" schema:"-"`
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorType, e.Description)
}
