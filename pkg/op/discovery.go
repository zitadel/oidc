package op

import (
	"net/http"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/utils"
)

func discoveryHandler(c Configuration, s Signer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Discover(w, CreateDiscoveryConfig(c, s))
	}
}

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	utils.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(c Configuration, s Signer) *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                c.Issuer(),
		AuthorizationEndpoint: c.AuthorizationEndpoint().Absolute(c.Issuer()),
		TokenEndpoint:         c.TokenEndpoint().Absolute(c.Issuer()),
		IntrospectionEndpoint: c.IntrospectionEndpoint().Absolute(c.Issuer()),
		UserinfoEndpoint:      c.UserinfoEndpoint().Absolute(c.Issuer()),
		EndSessionEndpoint:    c.EndSessionEndpoint().Absolute(c.Issuer()),
		// CheckSessionIframe: c.TokenEndpoint().Absolute(c.Issuer())(c.CheckSessionIframe),
		JwksURI:                           c.KeysEndpoint().Absolute(c.Issuer()),
		ScopesSupported:                   Scopes(c),
		ResponseTypesSupported:            ResponseTypes(c),
		GrantTypesSupported:               GrantTypes(c),
		ClaimsSupported:                   SupportedClaims(c),
		IDTokenSigningAlgValuesSupported:  SigAlgorithms(s),
		SubjectTypesSupported:             SubjectTypes(c),
		TokenEndpointAuthMethodsSupported: AuthMethods(c),
		CodeChallengeMethodsSupported:     CodeChallengeMethods(c),
	}
}

var DefaultSupportedScopes = []string{
	oidc.ScopeOpenID,
	oidc.ScopeProfile,
	oidc.ScopeEmail,
	oidc.ScopePhone,
	oidc.ScopeAddress,
}

func Scopes(c Configuration) []string {
	return DefaultSupportedScopes //TODO: config
}

func ResponseTypes(c Configuration) []string {
	return []string{
		string(oidc.ResponseTypeCode),
		string(oidc.ResponseTypeIDTokenOnly),
		string(oidc.ResponseTypeIDToken),
	} //TODO: ok for now, check later if dynamic needed
}

func GrantTypes(c Configuration) []string {
	grantTypes := []string{
		string(oidc.GrantTypeCode),
	}
	if c.GrantTypeTokenExchangeSupported() {
		grantTypes = append(grantTypes, string(oidc.GrantTypeTokenExchange))
	}
	if c.GrantTypeJWTAuthorizationSupported() {
		grantTypes = append(grantTypes, string(oidc.GrantTypeBearer))
	}
	return grantTypes
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

func AuthMethods(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodNone,
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPostSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPost)
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func CodeChallengeMethods(c Configuration) []oidc.CodeChallengeMethod {
	codeMethods := make([]oidc.CodeChallengeMethod, 0, 1)
	if c.CodeMethodS256Supported() {
		codeMethods = append(codeMethods, oidc.CodeChallengeMethodS256)
	}
	return codeMethods
}
