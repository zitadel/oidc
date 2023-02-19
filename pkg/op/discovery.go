package op

import (
	"context"
	"net/http"

	"gopkg.in/square/go-jose.v2"

	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type DiscoverStorage interface {
	SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error)
}

var DefaultSupportedScopes = []string{
	oidc.ScopeOpenID,
	oidc.ScopeProfile,
	oidc.ScopeEmail,
	oidc.ScopePhone,
	oidc.ScopeAddress,
	oidc.ScopeOfflineAccess,
}

func discoveryHandler(c Configuration, s DiscoverStorage) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Discover(w, CreateDiscoveryConfig(r, c, s))
	}
}

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	httphelper.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(r *http.Request, config Configuration, storage DiscoverStorage) *oidc.DiscoveryConfiguration {
	issuer := config.IssuerFromRequest(r)
	return &oidc.DiscoveryConfiguration{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      config.AuthorizationEndpoint().Absolute(issuer),
		TokenEndpoint:                              config.TokenEndpoint().Absolute(issuer),
		IntrospectionEndpoint:                      config.IntrospectionEndpoint().Absolute(issuer),
		UserinfoEndpoint:                           config.UserinfoEndpoint().Absolute(issuer),
		RevocationEndpoint:                         config.RevocationEndpoint().Absolute(issuer),
		EndSessionEndpoint:                         config.EndSessionEndpoint().Absolute(issuer),
		JwksURI:                                    config.KeysEndpoint().Absolute(issuer),
		ScopesSupported:                            config.SupportedScopes(),
		ResponseTypesSupported:                     ResponseTypes(config),
		GrantTypesSupported:                        GrantTypes(config),
		SubjectTypesSupported:                      SubjectTypes(config),
		IDTokenSigningAlgValuesSupported:           SigAlgorithms(r.Context(), storage),
		RequestObjectSigningAlgValuesSupported:     RequestObjectSigAlgorithms(config),
		TokenEndpointAuthMethodsSupported:          AuthMethodsTokenEndpoint(config),
		TokenEndpointAuthSigningAlgValuesSupported: TokenSigAlgorithms(config),
		IntrospectionEndpointAuthSigningAlgValuesSupported: IntrospectionSigAlgorithms(config),
		IntrospectionEndpointAuthMethodsSupported:          AuthMethodsIntrospectionEndpoint(config),
		RevocationEndpointAuthSigningAlgValuesSupported:    RevocationSigAlgorithms(config),
		RevocationEndpointAuthMethodsSupported:             AuthMethodsRevocationEndpoint(config),
		ClaimsSupported:                                    SupportedClaims(config),
		CodeChallengeMethodsSupported:                      CodeChallengeMethods(config),
		UILocalesSupported:                                 config.SupportedUILocales(),
		RequestParameterSupported:                          config.RequestObjectSupported(),
	}
}

func ResponseTypes(c Configuration) []string {
	return []string{
		string(oidc.ResponseTypeCode),
		string(oidc.ResponseTypeIDTokenOnly),
		string(oidc.ResponseTypeIDToken),
	} // TODO: ok for now, check later if dynamic needed
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

func SubjectTypes(c Configuration) []string {
	return []string{"public"} //TODO: config
}

func SigAlgorithms(ctx context.Context, storage DiscoverStorage) []string {
	algorithms, err := storage.SignatureAlgorithms(ctx)
	if err != nil {
		return nil
	}
	algs := make([]string, len(algorithms))
	for i, algorithm := range algorithms {
		algs[i] = string(algorithm)
	}
	return algs
}

func RequestObjectSigAlgorithms(c Configuration) []string {
	if !c.RequestObjectSupported() {
		return nil
	}
	return c.RequestObjectSigningAlgorithmsSupported()
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

func IntrospectionSigAlgorithms(c Configuration) []string {
	if !c.IntrospectionAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.IntrospectionEndpointSigningAlgorithmsSupported()
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

func RevocationSigAlgorithms(c Configuration) []string {
	if !c.RevocationAuthMethodPrivateKeyJWTSupported() {
		return nil
	}
	return c.RevocationEndpointSigningAlgorithmsSupported()
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

func SupportedClaims(c Configuration) []string {
	return []string{ // TODO: config
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

func CodeChallengeMethods(c Configuration) []oidc.CodeChallengeMethod {
	codeMethods := make([]oidc.CodeChallengeMethod, 0, 1)
	if c.CodeMethodS256Supported() {
		codeMethods = append(codeMethods, oidc.CodeChallengeMethodS256)
	}
	return codeMethods
}
