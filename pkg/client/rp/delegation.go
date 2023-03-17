package rp

import (
	"github.com/zitadel/oidc/v3/pkg/oidc/grants/tokenexchange"
)

// DelegationTokenRequest is an implementation of TokenExchangeRequest
// it exchanges an "urn:ietf:params:oauth:token-type:access_token" with an optional
// "urn:ietf:params:oauth:token-type:access_token" actor token for an
// "urn:ietf:params:oauth:token-type:access_token" delegation token
func DelegationTokenRequest(subjectToken string, opts ...tokenexchange.TokenExchangeOption) *tokenexchange.TokenExchangeRequest {
	return tokenexchange.NewTokenExchangeRequest(subjectToken, tokenexchange.AccessTokenType, opts...)
}
