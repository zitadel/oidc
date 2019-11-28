package op

import (
	"net/http"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	utils.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(c Configuration) *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                c.Issuer(),
		AuthorizationEndpoint: c.AuthorizationEndpoint().Absolute(c.Issuer()),
		TokenEndpoint:         c.TokenEndpoint().Absolute(c.Issuer()),
		// IntrospectionEndpoint: c.Intro().Absolute(c.Issuer()),
		UserinfoEndpoint: c.UserinfoEndpoint().Absolute(c.Issuer()),
		// EndSessionEndpoint: c.TokenEndpoint().Absolute(c.Issuer())(c.EndSessionEndpoint),
		// CheckSessionIframe: c.TokenEndpoint().Absolute(c.Issuer())(c.CheckSessionIframe),
		// JwksURI:            c.TokenEndpoint().Absolute(c.Issuer())(c.JwksURI),
		// ScopesSupported:                   oidc.SupportedScopes,
		// ResponseTypesSupported:            responseTypes,
		// GrantTypesSupported:               oidc.SupportedGrantTypes,
		// ClaimsSupported:                   oidc.SupportedClaims,
		// IdTokenSigningAlgValuesSupported:  []string{keys.SigningAlgorithm},
		// SubjectTypesSupported:             []string{"public"},
		// TokenEndpointAuthMethodsSupported:

	}
}
