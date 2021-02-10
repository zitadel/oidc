package oidc

import (
	"golang.org/x/text/language"
)

const (
	DiscoveryEndpoint = "/.well-known/openid-configuration"
)

type DiscoveryConfiguration struct {
	Issuer                                             string                `json:"issuer,omitempty"`
	AuthorizationEndpoint                              string                `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      string                `json:"token_endpoint,omitempty"`
	IntrospectionEndpoint                              string                `json:"introspection_endpoint,omitempty"`
	UserinfoEndpoint                                   string                `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint                                 string                `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint                                 string                `json:"end_session_endpoint,omitempty"`
	CheckSessionIframe                                 string                `json:"check_session_iframe,omitempty"`
	JwksURI                                            string                `json:"jwks_uri,omitempty"`
	ScopesSupported                                    []string              `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string              `json:"response_types_supported"`
	ResponseModesSupported                             []string              `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []GrantType           `json:"grant_types_supported,omitempty"`
	ACRValuesSupported                                 []string              `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                              []string              `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported                   []string              `json:"id_token_signing_alg_values_supported,omitempty"`
	IDTokenEncryptionAlgValuesSupported                []string              `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported                []string              `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported                  []string              `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported               []string              `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported               []string              `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported             []string              `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported          []string              `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported          []string              `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []AuthMethod          `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string              `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported             []AuthMethod          `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string              `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []AuthMethod          `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string              `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                             []Display             `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                                []string              `json:"claim_types_supported,omitempty"`
	ClaimsSupported                                    []string              `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported                      []CodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
	ServiceDocumentation                               string                `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                             []language.Tag        `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                                 []language.Tag        `json:"ui_locales_supported,omitempty"`
	RequestParameterSupported                          bool                  `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported                       bool                  `json:"request_uri_parameter_supported"` //no omitempty because: If omitted, the default value is true
	RequireRequestURIRegistration                      bool                  `json:"require_request_uri_registration,omitempty"`
	OPPolicyURI                                        string                `json:"op_policy_uri,omitempty"`
	OPTermsOfServiceURI                                string                `json:"op_tos_uri,omitempty"`
}

type AuthMethod string

const (
	AuthMethodBasic         AuthMethod = "client_secret_basic"
	AuthMethodPost          AuthMethod = "client_secret_post"
	AuthMethodNone          AuthMethod = "none"
	AuthMethodPrivateKeyJWT AuthMethod = "private_key_jwt"
)

const (
	GrantTypeImplicit GrantType = "implicit"
)
