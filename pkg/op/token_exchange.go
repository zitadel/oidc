package op

import (
	"errors"
	"net/http"
)

//TokenExchange will handle the OAuth 2.0 token exchange grant ("urn:ietf:params:oauth:grant-type:token-exchange")
func TokenExchange(w http.ResponseWriter, r *http.Request, exchanger Exchanger) {
	RequestError(w, r, errors.New("unimplemented"))
}
