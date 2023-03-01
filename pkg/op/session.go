package op

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gobwas/glob"

	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
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
	err = ender.Storage().TerminateSession(r.Context(), session.UserID, session.ClientID)
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
	session := &EndSessionRequest{
		RedirectURI: ender.DefaultLogoutRedirectURI(),
	}
	if req.IdTokenHint != "" {
		claims, err := VerifyIDTokenHint(ctx, req.IdTokenHint, ender.IDTokenHintVerifier())
		if err != nil {
			return nil, oidc.ErrInvalidRequest().WithDescription("id_token_hint invalid").WithParent(err)
		}
		session.UserID = claims.GetSubject()
		if req.ClientID != "" && req.ClientID != claims.GetAuthorizedParty() {
			return nil, oidc.ErrInvalidRequest().WithDescription("client_id does not match azp of id_token_hint")
		}
		req.ClientID = claims.GetAuthorizedParty()
	}
	if req.ClientID != "" {
		client, err := ender.Storage().GetClientByClientID(ctx, req.ClientID)
		if err != nil {
			return nil, oidc.DefaultToServerError(err, "")
		}
		session.ClientID = client.GetID()
		if req.PostLogoutRedirectURI != "" {
			if err := ValidateEndSessionPostLogoutRedirectURI(req.PostLogoutRedirectURI, client); err != nil {
				return nil, err
			}
			session.RedirectURI = req.PostLogoutRedirectURI
		}
	}
	if req.State != "" {
		redirect, err := url.Parse(session.RedirectURI)
		if err != nil {
			return nil, oidc.DefaultToServerError(err, "")
		}
		session.RedirectURI = mergeQueryParams(redirect, url.Values{"state": {req.State}})
	}
	return session, nil
}

func ValidateEndSessionPostLogoutRedirectURI(postLogoutRedirectURI string, client Client) error {
	for _, uri := range client.PostLogoutRedirectURIs() {
		if uri == postLogoutRedirectURI {
			return nil
		}
	}
	if globClient, ok := client.(HasRedirectGlobs); ok {
		for _, uriGlob := range globClient.PostLogoutRedirectURIGlobs() {
			matcher, err := glob.Compile(uriGlob)
			if err != nil {
				return oidc.ErrServerError().WithParent(err)
			}
			if matcher.Match(postLogoutRedirectURI) {
				return nil
			}
		}
	}
	return oidc.ErrInvalidRequest().WithDescription("post_logout_redirect_uri invalid")
}
