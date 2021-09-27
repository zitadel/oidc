package op

import (
	"context"
	"net/http"

	httphelper "github.com/caos/oidc/pkg/http"
	"github.com/caos/oidc/pkg/oidc"
)

type SessionEnder interface {
	Decoder() httphelper.Decoder
	Storage() Storage
	IDTokenHintVerifier() IDTokenHintVerifier
	DefaultLogoutRedirectURI() string
}

func endSessionHandler(ender SessionEnder) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		EndSession(w, r, ender)
	}
}

func EndSession(w http.ResponseWriter, r *http.Request, ender SessionEnder) {
	req, err := ParseEndSessionRequest(r, ender.Decoder())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := ValidateEndSessionRequest(r.Context(), req, ender)
	if err != nil {
		RequestError(w, r, err)
		return
	}
	var clientID string
	if session.Client != nil {
		clientID = session.Client.GetID()
	}
	err = ender.Storage().TerminateSession(r.Context(), session.UserID, clientID)
	if err != nil {
		RequestError(w, r, oidc.DefaultToServerError(err, "error terminating session"))
		return
	}
	http.Redirect(w, r, session.RedirectURI, http.StatusFound)
}

func ParseEndSessionRequest(r *http.Request, decoder httphelper.Decoder) (*oidc.EndSessionRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error parsing form").WithParent(err)
	}
	req := new(oidc.EndSessionRequest)
	err = decoder.Decode(req, r.Form)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("error decoding form").WithParent(err)
	}
	return req, nil
}

func ValidateEndSessionRequest(ctx context.Context, req *oidc.EndSessionRequest, ender SessionEnder) (*EndSessionRequest, error) {
	session := new(EndSessionRequest)
	if req.IdTokenHint == "" {
		return session, nil
	}
	claims, err := VerifyIDTokenHint(ctx, req.IdTokenHint, ender.IDTokenHintVerifier())
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("id_token_hint invalid").WithParent(err)
	}
	session.UserID = claims.GetSubject()
	session.Client, err = ender.Storage().GetClientByClientID(ctx, claims.GetAuthorizedParty())
	if err != nil {
		return nil, oidc.DefaultToServerError(err, "")
	}
	if req.PostLogoutRedirectURI == "" {
		session.RedirectURI = ender.DefaultLogoutRedirectURI()
		return session, nil
	}
	for _, uri := range session.Client.PostLogoutRedirectURIs() {
		if uri == req.PostLogoutRedirectURI {
			session.RedirectURI = uri + "?state=" + req.State
			return session, nil
		}
	}
	return nil, oidc.ErrInvalidRequest().WithDescription("post_logout_redirect_uri invalid")
}
