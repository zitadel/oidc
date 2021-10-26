package oidc

type RevocationRequest struct {
	Token         string `schema:"token"`
	TokenTypeHint string `schema:"token_type_hint"`
}
