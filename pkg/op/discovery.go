package op

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	jose "github.com/go-jose/go-jose/v4"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
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

// DefaultSupportedResponseTypes are the response types a provider advertises
// and accepts when [Config.SupportedResponseTypes] is not set.
var DefaultSupportedResponseTypes = []oidc.ResponseType{
	oidc.ResponseTypeCode,
	oidc.ResponseTypeIDTokenOnly,
	oidc.ResponseTypeIDToken,
}

// DefaultSupportedGrantTypes are the grant types a provider advertises and
// accepts when [Config.SupportedGrantTypes] is not set, extended by the
// optional grants enabled through the [Config] switches and storage
// capabilities. See [GrantTypes].
var DefaultSupportedGrantTypes = []oidc.GrantType{
	oidc.GrantTypeCode,
	oidc.GrantTypeImplicit,
}

func discoveryHandler(c Configuration, s DiscoverStorage) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		Discover(w, CreateDiscoveryConfig(r.Context(), c, s))
	}
}

func Discover(w http.ResponseWriter, config *oidc.DiscoveryConfiguration) {
	httphelper.MarshalJSON(w, config)
}

func CreateDiscoveryConfig(ctx context.Context, config Configuration, storage DiscoverStorage) *oidc.DiscoveryConfiguration {
	issuer := IssuerFromContext(ctx)
	return &oidc.DiscoveryConfiguration{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      config.AuthorizationEndpoint().Absolute(issuer),
		TokenEndpoint:                              config.TokenEndpoint().Absolute(issuer),
		IntrospectionEndpoint:                      config.IntrospectionEndpoint().Absolute(issuer),
		UserinfoEndpoint:                           config.UserinfoEndpoint().Absolute(issuer),
		RevocationEndpoint:                         config.RevocationEndpoint().Absolute(issuer),
		EndSessionEndpoint:                         config.EndSessionEndpoint().Absolute(issuer),
		JwksURI:                                    config.KeysEndpoint().Absolute(issuer),
		DeviceAuthorizationEndpoint:                config.DeviceAuthorizationEndpoint().Absolute(issuer),
		CheckSessionIframe:                         config.CheckSessionIframe().Absolute(issuer),
		ScopesSupported:                            Scopes(config),
		ResponseTypesSupported:                     ResponseTypes(config),
		GrantTypesSupported:                        GrantTypes(config),
		SubjectTypesSupported:                      SubjectTypes(config),
		IDTokenSigningAlgValuesSupported:           SigAlgorithms(ctx, storage),
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
		BackChannelLogoutSupported:                         config.BackChannelLogoutSupported(),
		BackChannelLogoutSessionSupported:                  config.BackChannelLogoutSessionSupported(),
	}
}

func createDiscoveryConfigV2(ctx context.Context, config Configuration, storage DiscoverStorage, endpoints *Endpoints) *oidc.DiscoveryConfiguration {
	issuer := IssuerFromContext(ctx)
	return &oidc.DiscoveryConfiguration{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      endpoints.Authorization.Absolute(issuer),
		TokenEndpoint:                              endpoints.Token.Absolute(issuer),
		IntrospectionEndpoint:                      endpoints.Introspection.Absolute(issuer),
		UserinfoEndpoint:                           endpoints.Userinfo.Absolute(issuer),
		RevocationEndpoint:                         endpoints.Revocation.Absolute(issuer),
		EndSessionEndpoint:                         endpoints.EndSession.Absolute(issuer),
		JwksURI:                                    endpoints.JwksURI.Absolute(issuer),
		DeviceAuthorizationEndpoint:                endpoints.DeviceAuthorization.Absolute(issuer),
		ScopesSupported:                            Scopes(config),
		ResponseTypesSupported:                     ResponseTypes(config),
		GrantTypesSupported:                        GrantTypes(config),
		SubjectTypesSupported:                      SubjectTypes(config),
		IDTokenSigningAlgValuesSupported:           SigAlgorithms(ctx, storage),
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
		BackChannelLogoutSupported:                         config.BackChannelLogoutSupported(),
		BackChannelLogoutSessionSupported:                  config.BackChannelLogoutSessionSupported(),
	}
}

func Scopes(c Configuration) []string {
	provider, ok := c.(*Provider)
	if ok && provider.config.SupportedScopes != nil {
		return provider.config.SupportedScopes
	}
	return slices.Clone(DefaultSupportedScopes)
}

// supportedResponseTypesConfiguration is implemented by [Provider] and by
// any wrapper that embeds it, which is what makes the assertion below
// decorator-safe: a wrapper whose dynamic type is not exactly *Provider
// still provides the promoted method, so its operator configuration cannot
// be silently dropped.
type supportedResponseTypesConfiguration interface {
	SupportedResponseTypes() []oidc.ResponseType
}

func ResponseTypes(c Configuration) []string {
	responseTypes := DefaultSupportedResponseTypes
	if configured, ok := c.(supportedResponseTypesConfiguration); ok {
		responseTypes = configured.SupportedResponseTypes()
	}
	strings := make([]string, len(responseTypes))
	for i, responseType := range responseTypes {
		strings[i] = string(responseType)
	}
	return strings
}

// SupportedResponseType reports whether the provider accepts the response type
// at the authorization endpoint and advertises it in its discovery document.
// Both read the same [Provider.SupportedResponseTypes], so the two cannot
// drift. Configurations that do not implement the method, or did not set
// [Config.SupportedResponseTypes], get the defaults.
func SupportedResponseType(c Configuration, responseType oidc.ResponseType) bool {
	configured, ok := c.(supportedResponseTypesConfiguration)
	if !ok {
		return slices.Contains(DefaultSupportedResponseTypes, responseType)
	}
	return slices.Contains(configured.SupportedResponseTypes(), responseType)
}

// supportedGrantTypesConfiguration is the decorator-safe accessor for the
// operator's [Config.SupportedGrantTypes] list; see
// supportedResponseTypesConfiguration for why it is an optional interface
// instead of a concrete type assertion.
type supportedGrantTypesConfiguration interface {
	ConfiguredGrantTypes() []oidc.GrantType
}

func GrantTypes(c Configuration) []oidc.GrantType {
	candidates := DefaultSupportedGrantTypes
	configured, hasList := c.(supportedGrantTypesConfiguration)
	if hasList && configured.ConfiguredGrantTypes() != nil {
		// The explicit list is intersected with the server's actual
		// capabilities, so the discovery document cannot advertise a grant
		// the token endpoint would refuse.
		candidates = configured.ConfiguredGrantTypes()
	}
	grantTypes := make([]oidc.GrantType, 0, len(candidates)+5)
	for _, grantType := range candidates {
		if SupportedGrantType(c, grantType) {
			grantTypes = append(grantTypes, grantType)
		}
	}
	if hasList && configured.ConfiguredGrantTypes() != nil {
		// The authorization code flow is the only flow the provider's
		// callback and token endpoint are built around, and OpenID Connect
		// Core section 2 requires an OP to support it, so it cannot be
		// turned off: it is advertised and served even when the explicit
		// list omits it.
		if !slices.ContainsFunc(grantTypes, func(gt oidc.GrantType) bool {
			return gt == oidc.GrantTypeCode
		}) {
			grantTypes = append(grantTypes, oidc.GrantTypeCode)
		}
		return grantTypes
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
	if c.GrantTypeDeviceCodeSupported() {
		grantTypes = append(grantTypes, oidc.GrantTypeDeviceCode)
	}
	return grantTypes
}

// SupportedGrantType reports whether the provider accepts the grant type at
// the token endpoint. When [Config.SupportedGrantTypes] is set, a grant type
// must be listed there and still be actually served by the server, so the
// discovery document and the token endpoint cannot drift.
func SupportedGrantType(c Configuration, grantType oidc.GrantType) bool {
	switch grantType {
	case oidc.GrantTypeCode:
		// The authorization code flow is the only flow the provider's
		// callback is built around, so it cannot be turned off.
		return true
	case oidc.GrantTypeImplicit:
		// The implicit grant is served by the authorization endpoint through
		// the id_token response types, so whether it is available follows
		// from the supported response types, not from the grant list.
		return SupportedResponseType(c, oidc.ResponseTypeIDToken) ||
			SupportedResponseType(c, oidc.ResponseTypeIDTokenOnly)
	case oidc.GrantTypeRefreshToken:
		return c.GrantTypeRefreshTokenSupported()
	case oidc.GrantTypeClientCredentials:
		return c.GrantTypeClientCredentialsSupported()
	case oidc.GrantTypeTokenExchange:
		return c.GrantTypeTokenExchangeSupported()
	case oidc.GrantTypeBearer:
		return c.GrantTypeJWTAuthorizationSupported()
	case oidc.GrantTypeDeviceCode:
		return c.GrantTypeDeviceCodeSupported()
	default:
		return false
	}
}

// servableResponseTypes are the response types the authorization endpoint can
// actually serve: the code flow through AuthResponseCode, and the two id_token
// flavors of the implicit flow through AuthResponseToken. Anything else a
// client can request would fall through to the token response path and be
// answered with tokens under the wrong response type, so an operator list
// containing a value outside this set is a configuration error.
var servableResponseTypes = map[oidc.ResponseType]struct{}{
	oidc.ResponseTypeCode:        {},
	oidc.ResponseTypeIDToken:     {},
	oidc.ResponseTypeIDTokenOnly: {},
}

// validateConfiguredResponseTypes rejects an operator [Config.SupportedResponseTypes]
// list containing a response type the authorization endpoint cannot serve.
// A typo or an unsupported extension would otherwise be advertised in the
// discovery document and accepted at the endpoint (if the client allows it),
// only to produce tokens under the wrong response type.
func validateConfiguredResponseTypes(config *Config) error {
	for _, responseType := range config.SupportedResponseTypes {
		if _, ok := servableResponseTypes[responseType]; !ok {
			return fmt.Errorf("config: unsupported response type %q in SupportedResponseTypes; supported values are %q, %q and %q",
				string(responseType),
				string(oidc.ResponseTypeCode),
				string(oidc.ResponseTypeIDToken),
				string(oidc.ResponseTypeIDTokenOnly))
		}
	}
	return nil
}

// grantTypeConfigured reports whether the grant type passes the operator's
// [Config.SupportedGrantTypes] list. A nil list imposes no restriction and
// leaves the [Config] switches and storage capabilities in charge, which is
// the behavior of previous versions.
func grantTypeConfigured(c Configuration, grantType oidc.GrantType) bool {
	configured, ok := c.(supportedGrantTypesConfiguration)
	if !ok || configured.ConfiguredGrantTypes() == nil {
		return true
	}
	return slices.Contains(configured.ConfiguredGrantTypes(), grantType)
}

func SubjectTypes(c Configuration) []string {
	return []string{"public"} // TODO: config
}

func SigAlgorithms(ctx context.Context, storage DiscoverStorage) []string {
	ctx, span := Tracer.Start(ctx, "SigAlgorithms")
	defer span.End()

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
	provider, ok := c.(*Provider)
	if ok && provider.config.SupportedClaims != nil {
		return provider.config.SupportedClaims
	}

	return slices.Clone(DefaultSupportedClaims)
}

func CodeChallengeMethods(c Configuration) []oidc.CodeChallengeMethod {
	codeMethods := make([]oidc.CodeChallengeMethod, 0, 1)
	if c.CodeMethodS256Supported() {
		codeMethods = append(codeMethods, oidc.CodeChallengeMethodS256)
	}
	return codeMethods
}
