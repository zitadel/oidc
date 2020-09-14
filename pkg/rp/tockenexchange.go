package rp

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/caos/oidc/pkg/oidc/grants/tokenexchange"
)

//TokenExchangeRP extends the `RelayingParty` interface for the *draft* oauth2 `Token Exchange`
type TokenExchangeRP interface {
	RelayingParty

	//TokenExchange implement the `Token Exchange Grant` exchanging some token for an other
	TokenExchange(context.Context, *tokenexchange.TokenExchangeRequest) (*oauth2.Token, error)
}

//DelegationTokenExchangeRP extends the `TokenExchangeRP` interface
//for the specific `delegation token` request
type DelegationTokenExchangeRP interface {
	TokenExchangeRP

	//DelegationTokenExchange implement the `Token Exchange Grant`
	//providing an access token in request for a `delegation` token for a given resource / audience
	DelegationTokenExchange(context.Context, string, ...tokenexchange.TokenExchangeOption) (*oauth2.Token, error)
}

//TokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange (draft)
func TokenExchange(ctx context.Context, request *tokenexchange.TokenExchangeRequest, rp RelayingParty) (newToken *oauth2.Token, err error) {
	return CallTokenEndpoint(request, rp)
}

//DelegationTokenExchange is the `TokenExchangeRP` interface implementation
//handling the oauth2 token exchange for a delegation token (draft)
func DelegationTokenExchange(ctx context.Context, subjectToken string, rp RelayingParty, reqOpts ...tokenexchange.TokenExchangeOption) (newToken *oauth2.Token, err error) {
	return TokenExchange(ctx, DelegationTokenRequest(subjectToken, reqOpts...), rp)
}
