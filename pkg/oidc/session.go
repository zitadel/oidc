package oidc

// EndSessionRequest for the RP-Initiated Logout according to:
//https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
type EndSessionRequest struct {
	IdTokenHint           string `schema:"id_token_hint"`
	ClientID              string `schema:"client_id"`
	PostLogoutRedirectURI string `schema:"post_logout_redirect_uri"`
	State                 string `schema:"state"`
}
