package op

import (
	"net/http"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	utils.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(c Configuration, s Signer) *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                c.Issuer(),
		AuthorizationEndpoint: c.AuthorizationEndpoint().Absolute(c.Issuer()),
		TokenEndpoint:         c.TokenEndpoint().Absolute(c.Issuer()),
		// IntrospectionEndpoint: c.Intro().Absolute(c.Issuer()),
		UserinfoEndpoint: c.UserinfoEndpoint().Absolute(c.Issuer()),
		// EndSessionEndpoint: c.TokenEndpoint().Absolute(c.Issuer())(c.EndSessionEndpoint),
		// CheckSessionIframe: c.TokenEndpoint().Absolute(c.Issuer())(c.CheckSessionIframe),
		JwksURI:                c.KeysEndpoint().Absolute(c.Issuer()),
		ScopesSupported:        scopes(c),
		ResponseTypesSupported: responseTypes(c),
		GrantTypesSupported:    grantTypes(c),
		// ClaimsSupported:                   oidc.SupportedClaims,
		IDTokenSigningAlgValuesSupported:  sigAlgorithms(s),
		SubjectTypesSupported:             subjectTypes(c),
		TokenEndpointAuthMethodsSupported: authMethods(c.AuthMethodBasicSupported(), c.AuthMethodPostSupported()),
	}
}

func scopes(c Configuration) []string {
	return []string{
		"openid",
		"profile",
		"email",
		"phone",
	} //TODO: config
}

func responseTypes(c Configuration) []string {
	return []string{
		"code",
		"id_token",
		// "code token",
		// "code id_token",
		"id_token token",
		// "code id_token token"
	}
}

func grantTypes(c Configuration) []string {
	return []string{
		"client_credentials",
		"authorization_code",
		// "password",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
}

func sigAlgorithms(s Signer) []string {
	return []string{string(s.SignatureAlgorithm())}
}

func subjectTypes(c Configuration) []string {
	return []string{"public"} //TODO: config
}

func authMethods(basic, post bool) []string {
	authMethods := make([]string, 0, 2)
	if basic {
		// if c.AuthMethodBasicSupported() {
		authMethods = append(authMethods, authMethodBasic)
	}
	if post {
		// if c.AuthMethodPostSupported() {
		authMethods = append(authMethods, authMethodPost)
	}
	return authMethods
}
