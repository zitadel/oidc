package oidc

type EndSessionRequest struct {
	IdTokenHint           string `schema:"id_token_hint"`
	PostLogoutRedirectURI string `schema:"post_logout_redirect_uri"`
	State                 string `schema:"state"`
}
