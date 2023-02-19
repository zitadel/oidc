package rp

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v2/pkg/oidc/grants/tokenexchange"
)

// TokenExchangeRP extends the `RelyingParty` interface for the *draft* oauth2 `Token Exchange`
type TokenExchangeRP interface {
	RelyingParty

	// TokenExchange implement the `Token Exchange Grant` exchanging some token for an other
	TokenExchange(context.Context, *tokenexchange.TokenExchangeRequest) (*oauth2.Token, error)
}

// DelegationTokenExchangeRP extends the `TokenExchangeRP` interface
// for the specific `delegation token` request
type DelegationTokenExchangeRP interface {
	TokenExchangeRP

	// DelegationTokenExchange implement the `Token Exchange Grant`
	// providing an access token in request for a `delegation` token for a given resource / audience
	DelegationTokenExchange(context.Context, string, ...tokenexchange.TokenExchangeOption) (*oauth2.Token, error)
}
