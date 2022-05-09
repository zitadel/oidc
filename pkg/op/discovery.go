package op

import (
	"net/http"

	httphelper "github.com/zitadel/oidc/pkg/http"
	"github.com/zitadel/oidc/pkg/oidc"
)

func discoveryHandler(c Configuration, s Signer) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Discover(w, CreateDiscoveryConfig(c, s))
	}
}

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	httphelper.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(c Configuration, s Signer) *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                                     c.Issuer(),
		AuthorizationEndpoint:                      c.AuthorizationEndpoint().Absolute(c.Issuer()),
		TokenEndpoint:                              c.TokenEndpoint().Absolute(c.Issuer()),
		IntrospectionEndpoint:                      c.IntrospectionEndpoint().Absolute(c.Issuer()),
		UserinfoEndpoint:                           c.UserinfoEndpoint().Absolute(c.Issuer()),
		RevocationEndpoint:                         c.RevocationEndpoint().Absolute(c.Issuer()),
		EndSessionEndpoint:                         c.EndSessionEndpoint().Absolute(c.Issuer()),
		JwksURI:                                    c.KeysEndpoint().Absolute(c.Issuer()),
		ScopesSupported:                            Scopes(c),
		ResponseTypesSupported:                     ResponseTypes(c),
		GrantTypesSupported:                        GrantTypes(c),
		SubjectTypesSupported:                      SubjectTypes(c),
		IDTokenSigningAlgValuesSupported:           SigAlgorithms(s),
		RequestObjectSigningAlgValuesSupported:     RequestObjectSigAlgorithms(c),
		TokenEndpointAuthMethodsSupported:          AuthMethodsTokenEndpoint(c),
		TokenEndpointAuthSigningAlgValuesSupported: TokenSigAlgorithms(c),
		IntrospectionEndpointAuthSigningAlgValuesSupported: IntrospectionSigAlgorithms(c),
		IntrospectionEndpointAuthMethodsSupported:          AuthMethodsIntrospectionEndpoint(c),
		RevocationEndpointAuthSigningAlgValuesSupported:    RevocationSigAlgorithms(c),
		RevocationEndpointAuthMethodsSupported:             AuthMethodsRevocationEndpoint(c),
		ClaimsSupported:                                    SupportedClaims(c),
		CodeChallengeMethodsSupported:                      CodeChallengeMethods(c),
		UILocalesSupported:                                 c.SupportedUILocales(),
		RequestParameterSupported:                          c.RequestObjectSupported(),
	}
}

var DefaultSupportedScopes = []string{
	oidc.ScopeOpenID,
	oidc.ScopeProfile,
	oidc.ScopeEmail,
	oidc.ScopePhone,
	oidc.ScopeAddress,
	oidc.ScopeOfflineAccess,
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

func GrantTypes(c Configuration) []oidc.GrantType {
	grantTypes := []oidc.GrantType{
		oidc.GrantTypeCode,
		oidc.GrantTypeImplicit,
	}
	if c.GrantTypeRefreshTokenSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeRefreshToken)
	}
	if c.GrantTypeClientCredentialsSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeClientCredentials)
	}
	if c.GrantTypeTokenExchangeSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeTokenExchange)
	}
	if c.GrantTypeJWTAuthorizationSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeBearer)
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

func AuthMethodsTokenEndpoint(c Configuration) []oidc.AuthMethod {
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

func TokenSigAlgorithms(c Configuration) []string {
	if !c.AuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.TokenEndpointSigningAlgorithmsSupported()
}

func AuthMethodsIntrospectionEndpoint(c Configuration) []oidc.AuthMethod {
	authMethods := []oidc.AuthMethod{
		oidc.AuthMethodBasic,
	}
	if c.AuthMethodPrivateKeyJWTSupported() {
		authMethods = append(authMethods, oidc.AuthMethodPrivateKeyJWT)
	}
	return authMethods
}

func AuthMethodsRevocationEndpoint(c Configuration) []oidc.AuthMethod {
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

func IntrospectionSigAlgorithms(c Configuration) []string {
	if !c.IntrospectionAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.IntrospectionEndpointSigningAlgorithmsSupported()
}

func RevocationSigAlgorithms(c Configuration) []string {
	if !c.RevocationAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.RevocationEndpointSigningAlgorithmsSupported()
}

func RequestObjectSigAlgorithms(c Configuration) []string {
	if !c.RequestObjectSupported() {
		return nil
	}
	return c.RequestObjectSigningAlgorithmsSupported()
}
