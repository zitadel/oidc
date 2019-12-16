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
		JwksURI:                           c.KeysEndpoint().Absolute(c.Issuer()),
		ScopesSupported:                   Scopes(c),
		ResponseTypesSupported:            ResponseTypes(c),
		GrantTypesSupported:               GrantTypes(c),
		ClaimsSupported:                   SupportedClaims(c),
		IDTokenSigningAlgValuesSupported:  SigAlgorithms(s),
		SubjectTypesSupported:             SubjectTypes(c),
		TokenEndpointAuthMethodsSupported: AuthMethods(c),
	}
}

const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopePhone   = "phone"
	ScopeAddress = "address"
)

var DefaultSupportedScopes = []string{
	ScopeOpenID,
	ScopeProfile,
	ScopeEmail,
	ScopePhone,
	ScopeAddress,
}

func Scopes(c Configuration) []string {
	return DefaultSupportedScopes //TODO: config
}

func ResponseTypes(c Configuration) []string {
	return []string{
		"code",
		"id_token",
		// "code token",
		// "code id_token",
		"id_token token",
		// "code id_token token"
	}
}

func GrantTypes(c Configuration) []string {
	return []string{
		"client_credentials",
		"authorization_code",
		// "password",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
}

func SupportedClaims(c Configuration) []string {
	return []string{ //TODO: config
		"sub",
		"aud",
		"exp",
		"iat",
		"iss",
		"auth_time",
		"nonce",
		"acr",
		"amr",
		"c_hash",
		"at_hash",
		"act",
		"scopes",
		"client_id",
		"azp",
		"preferred_username",
		"name",
		"family_name",
		"given_name",
		"locale",
		"email",
		"email_verified",
		"phone_number",
		"phone_number_verified",
	}
}

func SigAlgorithms(s Signer) []string {
	return []string{string(s.SignatureAlgorithm())}
}

func SubjectTypes(c Configuration) []string {
	return []string{"public"} //TODO: config
}

func AuthMethods(c Configuration) []string {
	authMethods := []string{
		string(AuthMethodBasic),
	}
	if c.AuthMethodPostSupported() {
		authMethods = append(authMethods, string(AuthMethodPost))
	}
	return authMethods
}
