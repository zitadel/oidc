package client

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// JWTProfileExchange handles the oauth2 jwt profile exchange
func JWTProfileExchange(ctx context.Context, jwtProfileGrantRequest *oidc.JWTProfileGrantRequest, caller TokenEndpointCaller) (*oauth2.Token, error) {
	return CallTokenEndpoint(ctx, jwtProfileGrantRequest, caller)
}

func ClientAssertionCodeOptions(assertion string) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_assertion", assertion),
		oauth2.SetAuthURLParam("client_assertion_type", oidc.ClientAssertionTypeJWTAssertion),
	}
}

func ClientAssertionFormAuthorization(assertion string) http.FormAuthorization {
	return func(values url.Values) {
		values.Set("client_assertion", assertion)
		values.Set("client_assertion_type", oidc.ClientAssertionTypeJWTAssertion)
	}
}
