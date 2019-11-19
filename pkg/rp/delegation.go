package rp

import (
	"github.com/caos/oidc/pkg/oidc/grants/tokenexchange"
)

//DelegationTokenRequest is an implementation of TokenExchangeRequest
//it exchanges a "urn:ietf:params:oauth:token-type:access_token" with an optional
//"urn:ietf:params:oauth:token-type:access_token" actor token for a
//"urn:ietf:params:oauth:token-type:access_token" delegation token
func DelegationTokenRequest(subjectToken string, opts ...tokenexchange.TokenExchangeOption) *tokenexchange.TokenExchangeRequest {
	return tokenexchange.NewTokenExchangeRequest(subjectToken, tokenexchange.AccessTokenType, opts...)
}
