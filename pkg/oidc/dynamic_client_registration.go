package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/internationalizedfield"
	"golang.org/x/text/language"
	"strings"
)

// ClientMetadata implements https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata,
// https://www.rfc-editor.org/rfc/rfc7591#section-2 and
// https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata.
//
// The Client Metadata values are used in two ways:
//
//   - as input values to registration requests (ClientRegistrationRequest), and
//   - as output values in registration responses and read responses (ClientInformationResponse).
type ClientMetadata struct {
	// Original fields suggested by RFC7591 (https://www.rfc-editor.org/rfc/rfc7591#section-2)

	// RedirectURIs is an array of redirection URI strings for use in redirect-based flows
	// such as the authorization code and implicit flows.
	// As required by [Section 2] of OAuth 2.0 [RFC6749], clients using flows with
	// redirection MUST register their redirection URI values.
	// Authorization servers that support dynamic registration for
	// redirect-based flows MUST implement support for this metadata
	// value.
	//
	// [Section 2]: https://www.rfc-editor.org/rfc/rfc7591#section-2
	// [RFC6749]: https://www.rfc-editor.org/rfc/rfc6749
	RedirectURIs []string `json:"redirect_uris"`

	// TokenEndpointAuthMethod is a string indicator of the requested authentication method for the
	// token endpoint.  Values defined by this specification are:
	//
	// 	- "none": The client is a public client as defined in OAuth 2.0,
	//    [Section 2.1], and does not have a client secret.
	//
	// 	- "client_secret_post": The client uses the HTTP POST parameters
	//    as defined in OAuth 2.0, [Section 2.3.1].
	//
	// 	- "client_secret_basic": The client uses HTTP Basic as defined in
	//    OAuth 2.0, [Section 2.3.1].
	//
	// Additional values can be defined via the IANA "OAuth Token
	// Endpoint Authentication Methods" registry established in
	// Section 4.2.  Absolute URIs can also be used as values for this
	// parameter without being registered.  If unspecified or omitted,
	// the default is "client_secret_basic", denoting the HTTP Basic
	// authentication scheme as specified in [Section 2.3.1] of OAuth 2.0.
	//
	// [Section 2.1]: https://www.rfc-editor.org/rfc/rfc7591#section-2.1
	// [Section 2.3.1]: https://www.rfc-editor.org/rfc/rfc7591#section-2.3.1
	TokenEndpointAuthMethod AuthMethod `json:"token_endpoint_auth_method"`

	// GrantTypes is an array of OAuth 2.0 grant type strings that the client can use at
	// the token endpoint.  These grant types are defined as follows:
	//
	// 	- "authorization_code": The authorization code grant type defined
	//    in OAuth 2.0, [Section 4.1].
	//
	// 	- "implicit": The implicit grant type defined in OAuth 2.0,
	//    [Section 4.2].
	//
	// 	- "password": The resource owner password credentials grant type
	//    defined in OAuth 2.0, [Section 4.3].
	//
	// 	- "client_credentials": The client credentials grant type defined
	//    in OAuth 2.0, [Section 4.4].
	//
	// 	- "refresh_token": The refresh token grant type defined in OAuth
	//    2.0, [Section 6].
	//
	// 	- "urn:ietf:params:oauth:grant-type:jwt-bearer": The JWT Bearer
	//    Token Grant Type defined in OAuth JWT Bearer Token Profiles
	//    [RFC7523].
	//
	// *  "urn:ietf:params:oauth:grant-type:saml2-bearer": The SAML 2.0
	//    Bearer Assertion Grant defined in OAuth SAML 2 Bearer Token
	//    Profiles [RFC7522].
	//
	// If the token endpoint is used in the grant type, the value of this
	// parameter MUST be the same as the value of the "grant_type"
	// parameter passed to the token endpoint defined in the grant type
	// definition.  Authorization servers MAY allow for other values as
	// defined in the grant type extension process described in OAuth
	// 2.0, [Section 4.5].  If omitted, the default behavior is that the
	// client will use only the "authorization_code" Grant Type.
	//
	// [Section 4.1]: https://www.rfc-editor.org/rfc/rfc7591#section-4.1
	// [Section 4.2]: https://www.rfc-editor.org/rfc/rfc7591#section-4.2
	// [Section 4.3]: https://www.rfc-editor.org/rfc/rfc7591#section-4.3
	// [Section 4.4]: https://www.rfc-editor.org/rfc/rfc7591#section-4.4
	// [Section 4.5]: https://www.rfc-editor.org/rfc/rfc7591#section-4.5
	// [Section 6]: https://www.rfc-editor.org/rfc/rfc7591#section-6
	// [RFC7523]: https://www.rfc-editor.org/rfc/rfc7523
	// [RFC7522]: https://www.rfc-editor.org/rfc/rfc7522
	GrantTypes []GrantType `json:"grant_types"`

	// ResponseTypes is an array of the OAuth 2.0 response type strings that the client can
	// use at the authorization endpoint.  These response types are
	// defined as follows:
	//
	// 	- "code": The authorization code response type defined in OAuth
	//    2.0, [Section 4.1].
	//
	// 	- "token": The implicit response type defined in OAuth 2.0,
	//    [Section 4.2].
	//
	// If the authorization endpoint is used by the grant type, the value
	// of this parameter MUST be the same as the value of the
	// "response_type" parameter passed to the authorization endpoint
	// defined in the grant type definition.  Authorization servers MAY
	// allow for other values as defined in the grant type extension
	// process is described in OAuth 2.0, [Section 4.5].  If omitted, the
	// default is that the client will use only the "code" response type.
	//
	// [Section 4.1]: https://www.rfc-editor.org/rfc/rfc7591#section-4.1
	// [Section 4.2]: https://www.rfc-editor.org/rfc/rfc7591#section-4.2
	// [Section 4.5]: https://www.rfc-editor.org/rfc/rfc7591#section-4.5
	ResponseTypes []ResponseType `json:"response_types"`

	// ClientName is a human-readable string name of the client to be presented to the
	// end-user during authorization.  If omitted, the authorization
	// server MAY display the raw "client_id" value to the end-user
	// instead.  It is RECOMMENDED that clients always send this field.
	// The value of this field MAY be internationalized, as described in
	// [Section 2.2].
	//
	// [Section 2.2]: https://www.rfc-editor.org/rfc/rfc7591#section-2.2
	ClientName internationalizedfield.InternationalizedField `json:"client_name"`

	// ClientURI is a URL string of a web page providing information about the client.
	// If present, the server SHOULD display this URL to the end-user in
	// a clickable fashion.  It is RECOMMENDED that clients always send
	// this field.  The value of this field MUST point to a valid web
	// page.  The value of this field MAY be internationalized, as
	// described in [Section 2.2].
	//
	// [Section 2.2]: https://www.rfc-editor.org/rfc/rfc7591#section-2.2
	ClientURI internationalizedfield.InternationalizedField `json:"client_uri"`

	// LogoURI is a URL string that references a logo for the client.  If present, the
	// server SHOULD display this image to the end-user during approval.
	// The value of this field MUST point to a valid image file.  The
	// value of this field MAY be internationalized, as described in
	// [Section 2.2].
	//
	// [Section 2.2]: https://www.rfc-editor.org/rfc/rfc7591#section-2.2
	LogoURI internationalizedfield.InternationalizedField `json:"logo_uri"`

	// Scope is a string containing a space-separated list of scope values (as
	// described in [Section 3.3] of OAuth 2.0 [RFC6749]) that the client
	// can use when requesting access tokens.  The semantics of values in
	// this list are service specific.  If omitted, an authorization
	// server MAY register a client with a default set of scopes.
	//
	// [Section 3.3]: https://www.rfc-editor.org/rfc/rfc7591#section-3.3
	// [RFC6749]: https://www.rfc-editor.org/rfc/rfc6749
	Scope string `json:"scope"`

	// Contacts is an array of strings representing ways to contact people responsible
	// for this client, typically email addresses.  The authorization
	// server MAY make these contact addresses available to end-users for
	// support requests for the client.  See [Section 6] for information on
	// Privacy Considerations.
	//
	// [Section 6]: https://www.rfc-editor.org/rfc/rfc7591#section-6
	Contacts []string `json:"contacts"`

	// TOSURI is a URL string that points to a human-readable terms of service
	// document for the client that describes a contractual relationship
	// between the end-user and the client that the end-user accepts when
	// authorizing the client.  The authorization server SHOULD display
	// this URL to the end-user if it is provided.  The value of this
	// field MUST point to a valid web page.  The value of this field MAY
	// be internationalized, as described in [Section 2.2].
	//
	// [Section 2.2]: https://www.rfc-editor.org/rfc/rfc7591#section-2.2
	TOSURI internationalizedfield.InternationalizedField `json:"tos_uri"`

	// PolicyURI is a URL string that points to a human-readable privacy policy document
	// that describes how the deployment organization collects, uses,
	// retains, and discloses personal data.  The authorization server
	// SHOULD display this URL to the end-user if it is provided.  The
	// value of this field MUST point to a valid web page.  The value of
	// this field MAY be internationalized, as described in [Section 2.2].
	//
	// [Section 2.2]: https://www.rfc-editor.org/rfc/rfc7591#section-2.2
	PolicyURI internationalizedfield.InternationalizedField `json:"policy_uri"`

	// JWKSURI is a URL string referencing the client's JSON Web Key (JWK) Set
	// [RFC7517] document, which contains the client's public keys.  The
	// value of this field MUST point to a valid JWK Set document.  These
	// keys can be used by higher-level protocols that use signing or
	// encryption.  For instance, these keys might be used by some
	// applications for validating signed requests made to the token
	// endpoint when using JWTs for client authentication [RFC7523].  Use
	// of this parameter is preferred over the "jwks" parameter, as it
	// allows for easier key rotation.  The "jwks_uri" and "jwks"
	// parameters MUST NOT both be present in the same request or
	// response.
	//
	// [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
	// [RFC7523]: https://www.rfc-editor.org/rfc/rfc7523
	JWKSURI string `json:"jwks_uri"`

	// JWKS is the Client's JSON Web Key Set [RFC7517] document value, which contains
	// the client's public keys.  The value of this field MUST be a JSON
	// object containing a valid JWK Set.  These keys can be used by
	// higher-level protocols that use signing or encryption.  This
	// parameter is intended to be used by clients that cannot use the
	// "jwks_uri" parameter, such as native clients that cannot host
	// public URLs.  The "jwks_uri" and "jwks" parameters MUST NOT both
	// be present in the same request or response.
	//
	// [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
	JWKS jose.JSONWebKeySet `json:"jwks"`

	// SoftwareID is a unique identifier string (e.g., a Universally Unique Identifier
	// (UUID)) assigned by the client developer or software publisher
	// used by registration endpoints to identify the client software to
	// be dynamically registered.  Unlike "client_id", which is issued by
	// the authorization server and SHOULD vary between instances, the
	// "software_id" SHOULD remain the same for all instances of the
	// client software.  The "software_id" SHOULD remain the same across
	// multiple updates or versions of the same piece of software.  The
	// value of this field is not intended to be human readable and is
	// usually opaque to the client and authorization server.
	SoftwareID string `json:"software_id"`

	// SoftwareVersion is a version identifier string for the client software identified by
	// "software_id".  The value of the "software_version" SHOULD change
	// on any update to the client software identified by the same
	// "software_id".  The value of this field is intended to be compared
	// using string equality matching and no other comparison semantics
	// are defined by this specification.  The value of this field is
	// outside the scope of this specification, but it is not intended to
	// be human readable and is usually opaque to the client and
	// authorization server.  The definition of what constitutes an
	// update to client software that would trigger a change to this
	// value is specific to the software itself and is outside the scope
	// of this specification.
	SoftwareVersion string `json:"software_version"`

	// Additional fields suggested by OpenID Connect Dynamic Client Registration 1.0
	// (https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata)

	// ApplicationType is a kind of the application.
	//
	// The default, if omitted, is op.ApplicationTypeWeb.
	//
	// The defined values are op.ApplicationTypeNative or op.ApplicationTypeWeb.
	//
	// Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris;
	// they MUST NOT use localhost as the hostname.
	//
	// Native Clients MUST only register redirect_uris using custom URI schemes or loopback URLs using the http scheme;
	// loopback URLs use localhost or the IP loopback literals 127.0.0.1 or [::1] as the hostname.
	//
	// Authorization Servers MAY place additional constraints on Native Clients.
	//
	// Authorization Servers MAY reject Redirection URI values using the http scheme, other than the loopback case for
	// Native Clients.
	//
	// The Authorization Server MUST verify that all the registered redirect_uris conform to these constraints.
	// This prevents sharing a Client ID across different types of Clients.
	//
	// OPTIONAL.
	//
	// N.B.: Cannot use op.ApplicationType because of cyclic imports.
	ApplicationType string `json:"application_type,omitempty"`

	// SectorIdentifierURI is a URL using the https scheme to be used in calculating
	// Pseudonymous Identifiers by the OP.
	// The URL references a file with a single JSON array of redirect_uri values. Please see [Section 5].
	// Providers that use pairwise sub (subject) values SHOULD utilize the sector_identifier_uri value provided
	// in the Subject Identifier calculation for pairwise identifiers.
	//
	// OPTIONAL.
	//
	// [Section 5]: https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// SubjectType is the subject_type requested for responses to this Client.
	// The subject_types_supported discovery parameter contains a list of the supported subject_type values for the OP.
	// Valid types include pairwise and public.
	//
	// OPTIONAL.
	SubjectType string `json:"subject_type,omitempty"`

	// IDTokenSignedResponseAlg is a JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client.
	// The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that
	// return no ID Token from the Authorization Endpoint (such as when only using the Authorization Code Flow).
	//The default, if omitted, is RS256.
	//The public key for validating the signature is provided by retrieving the JWK Set referenced by the
	// jwks_uri element from [OpenID Connect Discovery 1.0] [OpenID.Discovery].
	//
	// OPTIONAL.
	//
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	// [OpenID Connect Discovery 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Discovery
	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg,omitempty"`

	// IDTokenEncryptedResponseAlg is a JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this
	// Client. If this is requested, the response will be signed then encrypted, with the result being a Nested JWT,
	// as defined in [JWT].
	// The default, if omitted, is that no encryption is performed.
	//
	// OPTIONAL.
	//
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	// [JWT]: https://openid.net/specs/openid-connect-registration-1_0.html#JWT
	IDTokenEncryptedResponseAlg string `json:"id_token_encrypted_response_alg,omitempty"`

	// IDTokenEncryptedResponseEnc is a JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to
	// this Client.
	// If id_token_encrypted_response_alg is specified,
	// the default id_token_encrypted_response_enc value is A128CBC-HS256.
	// When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
	//
	// OPTIONAL.
	//
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	IDTokenEncryptedResponseEnc string `json:"id_token_encrypted_response_enc,omitempty"`

	// UserinfoSignedResponseAlg is a JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses.
	// If this is specified, the response will be JWT [JWT] serialized, and signed using JWS.
	// The default, if omitted, is for the UserInfo Response to return the Claims as a UTF-8 [RFC3629]
	// encoded JSON object using the application/json content-type.
	//
	// OPTIONAL.
	//
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	// [JWT]: https://openid.net/specs/openid-connect-registration-1_0.html#JWT
	// [RFC3629]: https://openid.net/specs/openid-connect-registration-1_0.html#RFC3629
	UserinfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty"`

	// UserinfoEncryptedResponseAlg is a JWE [JWE] alg algorithm [JWA] REQUIRED for encrypting UserInfo Responses.
	// If both signing and encryption are requested, the response will be signed then encrypted,
	// with the result being a Nested JWT, as defined in [JWT].
	// The default, if omitted, is that no encryption is performed.
	//
	// OPTIONAL.
	//
	// [JWE]: https://openid.net/specs/openid-connect-registration-1_0.html#JWE
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	// [JWT]: https://openid.net/specs/openid-connect-registration-1_0.html#JWT
	UserinfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg,omitempty"`

	// UserinfoEncryptedResponseEnc is a JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses.
	// If userinfo_encrypted_response_alg is specified,
	// the default userinfo_encrypted_response_enc value is A128CBC-HS256.
	// When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
	//
	// OPTIONAL.
	//
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	UserinfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc,omitempty"`

	// RequestObjectSigningAlg is a JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent
	// to the OP.
	// All Request Objects from this Client MUST be rejected, if not signed with this algorithm.
	// Request Objects are described in Section 6.1 of [OpenID Connect Core 1.0] [OpenID.Core].
	// This algorithm MUST be used both when the Request Object is passed by value (using the request parameter)
	// and when it is passed by reference (using the request_uri parameter).
	// Servers SHOULD support RS256. The value none MAY be used.
	// The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
	//
	// OPTIONAL.
	//
	// [JWS]: https://openid.net/specs/openid-connect-registration-1_0.html#JWS
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	// [OpenID Connect Core 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core
	RequestObjectSigningAlg string `json:"request_object_signing_alg,omitempty"`

	// RequestObjectEncryptionAlg is a JWE [JWE] alg algorithm [JWA]
	// the RP is declaring that it may use for encrypting Request Objects sent to the OP.
	// This parameter SHOULD be included when symmetric encryption will be used,
	// since this signals to the OP that a client_secret value needs to be returned from
	// which the symmetric key will be derived, that might not otherwise be returned.
	// The RP MAY still use other supported encryption algorithms or send unencrypted Request Objects,
	// even when this parameter is present.
	// If both signing and encryption are requested,
	// the Request Object will be signed then encrypted,
	// with the result being a Nested JWT, as defined in [JWT].
	// The default, if omitted, is that the RP is not declaring whether it might encrypt any Request Objects.
	//
	// OPTIONAL.
	//
	// [JWE]: https://openid.net/specs/openid-connect-registration-1_0.html#JWE
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	// [JWT]: https://openid.net/specs/openid-connect-registration-1_0.html#JWT
	RequestObjectEncryptionAlg string `json:"request_object_encryption_alg,omitempty"`

	// RequestObjectEncryptionEnc is a JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting
	// Request Objects sent to the OP.
	// If request_object_encryption_alg is specified, the default request_object_encryption_enc value is A128CBC-HS256.
	// When request_object_encryption_enc is included, request_object_encryption_alg MUST also be provided.
	//
	// OPTIONAL.
	//
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	RequestObjectEncryptionEnc string `json:"request_object_encryption_enc,omitempty"`

	// TokenEndpointAuthSigningAlg is a JWS [JWS] alg algorithm [JWA] that MUST be used for signing the
	// JWT [JWT] used to authenticate the Client at the Token Endpoint for the private_key_jwt
	// and client_secret_jwt authentication methods.
	// All Token Requests using these authentication methods from this Client MUST be rejected,
	// if the JWT is not signed with this algorithm.
	// Servers SHOULD support RS256.
	// The value none MUST NOT be used.
	// The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
	//
	// OPTIONAL.
	//
	// [JWS]: https://openid.net/specs/openid-connect-registration-1_0.html#JWS
	// [JWA]: https://openid.net/specs/openid-connect-registration-1_0.html#JWA
	// [JWT]: https://openid.net/specs/openid-connect-registration-1_0.html#JWT
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// DefaultMaxAge is the Default Maximum Authentication Age.
	// Specifies that the End-User MUST be actively authenticated
	// if the End-User was authenticated longer ago than the specified number of seconds.
	// The max_age request parameter overrides this default value.
	// If omitted, no default Maximum Authentication Age is specified.
	//
	// OPTIONAL.
	DefaultMaxAge int `json:"default_max_age,omitempty"`

	// RequireAuthTime is a boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED.
	// It is REQUIRED when the value is true.
	// (If this is false, the auth_time Claim can still be dynamically requested as
	// an individual Claim for the ID Token using the claims request parameter described in
	// Section 5.5.1 of [OpenID Connect Core 1.0] [OpenID.Core].)
	// If omitted, the default value is false.
	//
	// OPTIONAL.
	//
	// [OpenID Connect Core 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core
	RequireAuthTime bool `json:"require_auth_time,omitempty"`

	// DefaultACRValues are default requested Authentication Context Class Reference values.
	// Array of strings that specifies the default acr values that the OP is being requested to use for
	// processing requests from this Client, with the values appearing in order of preference.
	// The Authentication Context Class satisfied by the authentication performed is returned as the
	// acr Claim Value in the issued ID Token.
	// The acr Claim is requested as a Voluntary Claim by this parameter.
	// The acr_values_supported discovery element contains a list of the supported acr values supported by the OP.
	// Values specified in the acr_values request parameter or
	// an individual acr Claim request override these default values.
	DefaultACRValues []string `json:"default_acr_values,omitempty"`

	// InitiateLoginURI is a URI using the https scheme that a third party can use to initiate a login by the RP,
	// as specified in Section 4 of [OpenID Connect Core 1.0] [OpenID.Core].
	// The URI MUST accept requests via both GET and POST.
	// The Client MUST understand the login_hint and iss parameters and SHOULD support the target_link_uri parameter.
	//
	// OPTIONAL.
	//
	// [OpenID Connect Core 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#OpenID.Core
	InitiateLoginURI string `json:"initiate_login_uri,omitempty"`

	// RequestURIs is an array of request_uri values that are pre-registered by the RP for use at the OP.
	// These URLs MUST use the https scheme unless the target Request Object is
	// signed in a way that is verifiable by the OP.
	// Servers MAY cache the contents of the files referenced by these URIs and not retrieve them at the time
	// they are used in a request.
	// OPs can require that request_uri values used be pre-registered with
	// the require_request_uri_registration discovery parameter.
	// If the contents of the request file could ever change,
	// these URI values SHOULD include the base64url-encoded SHA-256 hash value of the file contents
	// referenced by the URI as the value of the URI fragment.
	// If the fragment value used for a URI changes,
	// that signals the server that its cached value for that URI with the old fragment value is no longer valid.
	RequestURIs []string `json:"request_uris,omitempty"`

	// Additional fields suggested by OpenID Connect RP-Initiated Logout 1.0
	// (https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ClientMetadata)

	// PostLogoutRedirectURIs is an array of URLs supplied by the RP
	// to which it MAY request that the End-User's User Agent be redirected using
	// the post_logout_redirect_uri parameter after a logout has been performed.
	// These URLs SHOULD use the https scheme and MAY contain port, path, and query parameter components;
	// however, they MAY use the http scheme, provided that the Client Type is confidential,
	// as defined in Section 2.1 of [OAuth 2.0] [RFC6749], and provided the OP allows the use of http RP URIs.
	//
	// [OAuth 2.0]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RFC6749
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`

	// ExtraParameters holds other extension parameters.
	ExtraParameters map[string]interface{}
}

func (c *ClientMetadata) UnmarshalJSON(data []byte) error {
	// Initialize maps to avoid nil pointer issues later.
	c.ClientName = internationalizedfield.New("client_name")
	c.ClientURI = internationalizedfield.New("client_uri")
	c.LogoURI = internationalizedfield.New("logo_uri")
	c.TOSURI = internationalizedfield.New("tos_uri")
	c.PolicyURI = internationalizedfield.New("policy_uri")
	c.ExtraParameters = make(map[string]interface{})

	// Unmarshal into a temporary map to inspect all keys.
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return fmt.Errorf("could not unmarshal raw data: %w", err)
	}

	// Iterate over all keys found in the JSON.
	for key, value := range rawMap {
		switch {
		case key == "redirect_uris":
			if err := json.Unmarshal(value, &c.RedirectURIs); err != nil {
				return err
			}
		case key == "token_endpoint_auth_method":
			if err := json.Unmarshal(value, &c.TokenEndpointAuthMethod); err != nil {
				// should we check against AuthMethodMap if token_endpoint_auth_method is valid?
				return err
			}
		case key == "grant_types":
			if err := json.Unmarshal(value, &c.GrantTypes); err != nil {
				// should we check against GrantTypeMap if grant_types is valid?
				return err
			}
		case key == "response_types":
			if err := json.Unmarshal(value, &c.ResponseTypes); err != nil {
				// should we check against ResponseTypeMap if response_types is valid?
				return err
			}
		case key == "client_name":
			var name string
			if err := json.Unmarshal(value, &name); err != nil {
				return err
			}
			c.ClientName.Items[language.Und] = name
		case strings.HasPrefix(key, "client_name#"):
			var name string
			if err := json.Unmarshal(value, &name); err != nil {
				return err
			}
			// This is a tagged name, e.g., "client_name#ja-Jpan-JP"
			// Split the key at the first '#' to get the language tag.
			parts := strings.SplitN(key, "#", 2)
			if len(parts) == 2 {
				langTag, err := language.Parse(parts[1])
				if err != nil {
					return fmt.Errorf("failed to parse language tag for client_name: %w", err)
				}
				c.ClientName.Items[langTag] = name
			} else {
				return fmt.Errorf("invalid client_name format: %q", key)
			}
		case key == "client_uri":
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			c.ClientURI.Items[language.Und] = uri
		case strings.HasPrefix(key, "client_uri#"):
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			// This is a tagged name, e.g., "client_uri#ja-Jpan-JP"
			// Split the key at the first '#' to get the language tag.
			parts := strings.SplitN(key, "#", 2)
			if len(parts) == 2 {
				langTag, err := language.Parse(parts[1])
				if err != nil {
					return fmt.Errorf("failed to parse language tag for client_uri: %w", err)
				}
				c.ClientURI.Items[langTag] = uri
			} else {
				return fmt.Errorf("invalid client_uri format: %q", key)
			}
		case key == "logo_uri":
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			c.LogoURI.Items[language.Und] = uri
		case strings.HasPrefix(key, "logo_uri#"):
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			// This is a tagged name, e.g., "logo_uri#ja-Jpan-JP"
			// Split the key at the first '#' to get the language tag.
			parts := strings.SplitN(key, "#", 2)
			if len(parts) == 2 {
				langTag, err := language.Parse(parts[1])
				if err != nil {
					return fmt.Errorf("failed to parse language tag for logo_uri: %w", err)
				}
				c.LogoURI.Items[langTag] = uri
			} else {
				return fmt.Errorf("invalid logo_uri format: %q", key)
			}
		case key == "scope":
			if err := json.Unmarshal(value, &c.Scope); err != nil {
				return err
			}
		case key == "contacts":
			if err := json.Unmarshal(value, &c.Contacts); err != nil {
				return err
			}
		case key == "tos_uri":
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			c.TOSURI.Items[language.Und] = uri
		case strings.HasPrefix(key, "tos_uri#"):
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			// This is a tagged name, e.g., "tos_uri#ja-Jpan-JP"
			// Split the key at the first '#' to get the language tag.
			parts := strings.SplitN(key, "#", 2)
			if len(parts) == 2 {
				langTag, err := language.Parse(parts[1])
				if err != nil {
					return fmt.Errorf("failed to parse language tag for tos_uri: %w", err)
				}
				c.TOSURI.Items[langTag] = uri
			} else {
				return fmt.Errorf("invalid client_uri format: %q", key)
			}
		case key == "policy_uri":
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			c.PolicyURI.Items[language.Und] = uri
		case strings.HasPrefix(key, "policy_uri#"):
			var uri string
			if err := json.Unmarshal(value, &uri); err != nil {
				return err
			}
			// This is a tagged name, e.g., "policy_uri#ja-Jpan-JP"
			// Split the key at the first '#' to get the language tag.
			parts := strings.SplitN(key, "#", 2)
			if len(parts) == 2 {
				langTag, err := language.Parse(parts[1])
				if err != nil {
					return fmt.Errorf("failed to parse language tag for policy_uri: %w", err)
				}
				c.PolicyURI.Items[langTag] = uri
			} else {
				return fmt.Errorf("invalid client_uri format: %q", key)
			}
		case key == "jwks_uri":
			if err := json.Unmarshal(value, &c.JWKSURI); err != nil {
				return err
			}
		case key == "jwks":
			if err := json.Unmarshal(value, &c.JWKS); err != nil {
				return err
			}
		case key == "software_id":
			if err := json.Unmarshal(value, &c.SoftwareID); err != nil {
				return err
			}
		case key == "software_version":
			if err := json.Unmarshal(value, &c.SoftwareVersion); err != nil {
				return err
			}
		case key == "application_type":
			if err := json.Unmarshal(value, &c.ApplicationType); err != nil {
				return err
			}
		case key == "sector_identifier_uri":
			if err := json.Unmarshal(value, &c.SectorIdentifierURI); err != nil {
				return err
			}
		case key == "subject_type":
			if err := json.Unmarshal(value, &c.SubjectType); err != nil {
				return err
			}
		case key == "id_token_signed_response_alg":
			if err := json.Unmarshal(value, &c.IDTokenSignedResponseAlg); err != nil {
				return err
			}
		case key == "id_token_encrypted_response_alg":
			if err := json.Unmarshal(value, &c.IDTokenEncryptedResponseAlg); err != nil {
				return err
			}
		case key == "id_token_encrypted_response_enc":
			if err := json.Unmarshal(value, &c.IDTokenEncryptedResponseEnc); err != nil {
				return err
			}
		case key == "userinfo_signed_response_alg":
			if err := json.Unmarshal(value, &c.UserinfoSignedResponseAlg); err != nil {
				return err
			}
		case key == "userinfo_encrypted_response_alg":
			if err := json.Unmarshal(value, &c.UserinfoEncryptedResponseAlg); err != nil {
				return err
			}
		case key == "userinfo_encrypted_response_enc":
			if err := json.Unmarshal(value, &c.UserinfoEncryptedResponseEnc); err != nil {
				return err
			}
		case key == "request_object_signing_alg":
			if err := json.Unmarshal(value, &c.RequestObjectEncryptionAlg); err != nil {
				return err
			}
		case key == "request_object_encryption_alg":
			if err := json.Unmarshal(value, &c.RequestObjectEncryptionAlg); err != nil {
				return err
			}
		case key == "request_object_encryption_enc":
			if err := json.Unmarshal(value, &c.RequestObjectEncryptionEnc); err != nil {
				return err
			}
		case key == "token_endpoint_auth_signing_alg":
			if err := json.Unmarshal(value, &c.TokenEndpointAuthSigningAlg); err != nil {
				return err
			}
		case key == "default_max_age":
			if err := json.Unmarshal(value, &c.DefaultMaxAge); err != nil {
				return err
			}
		case key == "require_auth_time":
			if err := json.Unmarshal(value, &c.RequireAuthTime); err != nil {
				return err
			}
		case key == "default_acr_values":
			if err := json.Unmarshal(value, &c.DefaultACRValues); err != nil {
				return err
			}
		case key == "initiate_login_uri":
			if err := json.Unmarshal(value, &c.InitiateLoginURI); err != nil {
				return err
			}
		case key == "request_uris":
			if err := json.Unmarshal(value, &c.RequestURIs); err != nil {
				return err
			}
		case key == "post_logout_redirect_uris":
			if err := json.Unmarshal(value, &c.PostLogoutRedirectURIs); err != nil {
				return err
			}
		default:
			// If the key didn't match any of the above, it's an extra parameter.
			var val interface{}
			if err := json.Unmarshal(value, &val); err != nil {
				return err
			}
			c.ExtraParameters[key] = val
		}
	}

	// Set default values

	if c.ApplicationType == "" {
		// The default, if omitted, is op.ApplicationTypeWeb.
		c.ApplicationType = "web"
	}

	if c.TokenEndpointAuthMethod == "" {
		// If unspecified or omitted,
		// the default is "client_secret_basic", denoting the HTTP Basic
		// authentication scheme as specified in [Section 2.3.1] of OAuth 2.0.
		//
		// [Section 2.3.1]: https://www.rfc-editor.org/rfc/rfc7591#section-2.3.1
		c.TokenEndpointAuthMethod = AuthMethodBasic
	}

	if len(c.GrantTypes) == 0 {
		// If omitted, the default behavior is that the client will use only the "authorization_code" Grant Type.
		c.GrantTypes = []GrantType{GrantTypeCode}
	}

	if len(c.ResponseTypes) == 0 {
		// If omitted, the default is that the client will use only the "code" response type.
		c.ResponseTypes = []ResponseType{ResponseTypeCode}
	}

	if c.JWKSURI != "" && len(c.JWKS.Keys) > 0 {
		// The "jwks_uri" and "jwks" parameters MUST NOT both be present in the same request or response.
		return errors.New("jwks_uri and jwks cannot both be present")
	}

	return nil
}

func (c ClientMetadata) MarshalJSON() ([]byte, error) {
	res := make(map[string]interface{})

	if len(c.RedirectURIs) > 0 {
		res["redirect_uris"] = c.RedirectURIs
	}

	if c.TokenEndpointAuthMethod != "" {
		res["token_endpoint_auth_method"] = c.TokenEndpointAuthMethod
	}

	if len(c.GrantTypes) > 0 {
		res["grant_types"] = c.GrantTypes
	}

	if len(c.ResponseTypes) > 0 {
		res["response_types"] = c.ResponseTypes
	}

	if len(c.ClientName.Items) > 0 {
		for lang, name := range c.ClientName.Items {
			if lang == language.Und {
				res[c.ClientName.FieldName] = name
			} else {
				res[fmt.Sprintf("%s#%s", c.ClientName.FieldName, lang)] = name
			}
		}
	}

	if len(c.ClientURI.Items) > 0 {
		for lang, uri := range c.ClientURI.Items {
			if lang == language.Und {
				res[c.ClientURI.FieldName] = uri
			} else {
				res[fmt.Sprintf("%s#%s", c.ClientURI.FieldName, lang)] = uri
			}
		}
	}

	if len(c.LogoURI.Items) > 0 {
		for lang, logo := range c.LogoURI.Items {
			if lang == language.Und {
				res[c.LogoURI.FieldName] = logo
			} else {
				res[fmt.Sprintf("%s#%s", c.LogoURI.FieldName, lang)] = logo
			}
		}
	}

	if c.Scope != "" {
		res["scope"] = c.Scope
	}

	if len(c.Contacts) > 0 {
		res["contacts"] = c.Contacts
	}

	if len(c.TOSURI.Items) > 0 {
		for lang, uri := range c.TOSURI.Items {
			if lang == language.Und {
				res[c.TOSURI.FieldName] = uri
			} else {
				res[fmt.Sprintf("%s#%s", c.TOSURI.FieldName, lang)] = uri
			}
		}
	}

	if len(c.PolicyURI.Items) > 0 {
		for lang, uri := range c.PolicyURI.Items {
			if lang == language.Und {
				res[c.PolicyURI.FieldName] = uri
			} else {
				res[fmt.Sprintf("%s#%s", c.PolicyURI.FieldName, lang)] = uri
			}
		}
	}

	if c.JWKSURI != "" {
		res["jwks_uri"] = c.JWKSURI
	}

	if len(c.JWKS.Keys) > 0 {
		res["jwks"] = c.JWKS
	}

	if c.SoftwareID != "" {
		res["software_id"] = c.SoftwareID
	}

	if c.SoftwareVersion != "" {
		res["software_version"] = c.SoftwareVersion
	}

	if c.ApplicationType != "" {
		res["application_type"] = c.ApplicationType
	}

	if c.SectorIdentifierURI != "" {
		res["sector_identifier_uri"] = c.SectorIdentifierURI
	}

	if c.SubjectType != "" {
		res["subject_type"] = c.SubjectType
	}

	if c.IDTokenSignedResponseAlg != "" {
		res["id_token_signed_response_alg"] = c.IDTokenSignedResponseAlg
	}

	if c.IDTokenEncryptedResponseAlg != "" {
		res["id_token_encrypted_response_alg"] = c.IDTokenEncryptedResponseAlg
	}

	if c.IDTokenEncryptedResponseEnc != "" {
		res["id_token_encrypted_response_enc"] = c.IDTokenEncryptedResponseEnc
	}

	if c.UserinfoSignedResponseAlg != "" {
		res["userinfo_signed_response_alg"] = c.UserinfoSignedResponseAlg
	}

	if c.UserinfoEncryptedResponseAlg != "" {
		res["userinfo_encrypted_response_alg"] = c.UserinfoEncryptedResponseAlg
	}

	if c.UserinfoEncryptedResponseEnc != "" {
		res["userinfo_encrypted_response_enc"] = c.UserinfoEncryptedResponseEnc
	}

	if c.RequestObjectSigningAlg != "" {
		res["request_object_signing_alg"] = c.RequestObjectSigningAlg
	}

	if c.RequestObjectEncryptionAlg != "" {
		res["request_object_encryption_alg"] = c.RequestObjectEncryptionAlg
	}

	if c.RequestObjectEncryptionEnc != "" {
		res["request_object_encryption_enc"] = c.RequestObjectEncryptionEnc
	}

	if c.TokenEndpointAuthSigningAlg != "" {
		res["token_endpoint_auth_signing_alg"] = c.TokenEndpointAuthSigningAlg
	}

	if c.DefaultMaxAge != 0 {
		res["default_max_age"] = c.DefaultMaxAge
	}

	if c.RequireAuthTime {
		res["require_auth_time"] = c.RequireAuthTime
	}

	if len(c.DefaultACRValues) > 0 {
		res["default_acr_values"] = c.DefaultACRValues
	}

	if c.InitiateLoginURI != "" {
		res["initiate_login_uri"] = c.InitiateLoginURI
	}

	if len(c.RequestURIs) > 0 {
		res["request_uris"] = c.RequestURIs
	}

	if len(c.PostLogoutRedirectURIs) > 0 {
		res["post_logout_redirect_uris"] = c.PostLogoutRedirectURIs
	}

	// Add extra parameters

	for key, value := range c.ExtraParameters {
		res[key] = value
	}

	return json.Marshal(res)
}

// ClientRegistrationRequest implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.1
// and https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationRequest
// 3.1 Client Registration Request.
type ClientRegistrationRequest struct {
	ClientMetadata

	// SoftwareStatement is a software statement containing client metadata values about the
	// client software as claims.  This is a string value containing the
	// entire signed JWT.
	SoftwareStatement string `json:"software_statement"`
}

func (c *ClientRegistrationRequest) UnmarshalJSON(data []byte) error {
	// Step 1: Parse raw JSON to separate software_statement
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Step 2: Extract software_statement if present
	if ssRaw, ok := rawMap["software_statement"]; ok {
		if err := json.Unmarshal(ssRaw, &c.SoftwareStatement); err != nil {
			return err
		}
		delete(rawMap, "software_statement") // Remove to avoid duplication
	}

	// Step 3: Marshal remaining fields and unmarshal into ClientMetadata
	remainingData, err := json.Marshal(rawMap)
	if err != nil {
		return err
	}
	return json.Unmarshal(remainingData, &c.ClientMetadata)
}

// ClientInformationResponse implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1,
// 3.2.1. Client Information Response and
// https://www.rfc-editor.org/rfc/rfc7592.html#section-3
// 3. Client Information Response.
type ClientInformationResponse struct {
	ClientMetadata

	// Original fields suggested by RFC7591 (https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1)

	// ClientID is a OAuth 2.0 client identifier string.  It SHOULD NOT be
	// currently valid for any other registered client, though an
	// authorization server MAY issue the same client identifier to
	// multiple instances of a registered client at its discretion.
	//
	// REQUIRED.
	ClientID string `json:"client_id"`

	// ClientSecret is a OAuth 2.0 client secret string.  If issued, this MUST
	// be unique for each "client_id" and SHOULD be unique for multiple
	// instances of a client using the same "client_id".  This value is
	// used by confidential clients to authenticate to the token
	// endpoint, as described in OAuth 2.0 [RFC6749, Section 2.3.1].
	//
	// [RFC6749, Section 2.3.1]: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
	//
	// OPTIONAL.
	ClientSecret string `json:"client_secret,omitempty"`

	// ClientIDIssuedAt is the time at which the client identifier was issued.  The
	// time is represented as the number of seconds from
	// 1970-01-01T00:00:00Z as measured in UTC until the date/time of
	// issuance.
	//
	// OPTIONAL.
	ClientIDIssuedAt int64 `json:"client_id_issued_at,omitempty"`

	// ClientSecretExpiresAt is the time at which the client
	// secret will expire or 0 if it will not expire.  The time is
	// represented as the number of seconds from 1970-01-01T00:00:00Z as
	// measured in UTC until the date/time of expiration.
	//
	// REQUIRED if "client_secret" is issued.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`
}

// UnmarshalJSON is only used for unit tests (to test MarshalJSON).
func (c *ClientInformationResponse) UnmarshalJSON(data []byte) error {
	// Step 1: Parse raw JSON to separate ClientInformationResponse-specific fields
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Step 2: Extract ClientInformationResponse-specific fields if present
	if ssRaw, ok := rawMap["client_id"]; ok {
		if err := json.Unmarshal(ssRaw, &c.ClientID); err != nil {
			return err
		}
		delete(rawMap, "client_id") // Remove to avoid duplication
	}

	if ssRaw, ok := rawMap["client_secret"]; ok {
		if err := json.Unmarshal(ssRaw, &c.ClientSecret); err != nil {
			return err
		}
		delete(rawMap, "client_secret") // Remove to avoid duplication
	}

	if ssRaw, ok := rawMap["client_id_issued_at"]; ok {
		if err := json.Unmarshal(ssRaw, &c.ClientIDIssuedAt); err != nil {
			return err
		}
		delete(rawMap, "client_id_issued_at") // Remove to avoid duplication
	}

	if ssRaw, ok := rawMap["client_secret_expires_at"]; ok {
		if err := json.Unmarshal(ssRaw, &c.ClientSecretExpiresAt); err != nil {
			return err
		}
		delete(rawMap, "client_secret_expires_at") // Remove to avoid duplication
	}

	// Step 3: Marshal remaining fields and unmarshal into ClientMetadata
	remainingData, err := json.Marshal(rawMap)
	if err != nil {
		return err
	}
	return json.Unmarshal(remainingData, &c.ClientMetadata)
}

func (c ClientInformationResponse) MarshalJSON() ([]byte, error) {
	// Marshal embedded ClientMetadata (includes custom logic)
	metaJSON, err := json.Marshal(c.ClientMetadata)
	if err != nil {
		return nil, err
	}

	// Convert to map to merge fields
	var combined map[string]interface{}
	if err := json.Unmarshal(metaJSON, &combined); err != nil {
		return nil, err
	}

	// Add ClientInformationResponse-specific fields
	combined["client_id"] = c.ClientID // always present
	if c.ClientSecret != "" {
		combined["client_secret"] = c.ClientSecret
		combined["client_secret_expires_at"] = c.ClientSecretExpiresAt // required if client_secret is issued
	}
	if c.ClientIDIssuedAt != 0 {
		combined["client_id_issued_at"] = c.ClientIDIssuedAt
	}

	return json.Marshal(combined)
}

// ClientRegistrationResponse implements
// https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
// 3.2.  Client Registration Response.
type ClientRegistrationResponse struct {
	ClientInformationResponse

	// RegistrationAccessToken is a Registration Access Token that can be used at the
	// Client Configuration Endpoint to perform subsequent operations upon the Client registration.ClientSecret
	//
	// OPTIONAL.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`

	// RegistrationClientURI is the location of the Client Configuration Endpoint where the
	// Registration Access Token can be used to perform subsequent operations upon the resulting Client registration.
	// This URL MUST use the https scheme.
	// Implementations MUST either return both a Client Configuration Endpoint and
	// a Registration Access Token or neither of them.
	//
	// OPTIONAL.
	RegistrationClientURI string `json:"registration_client_uri,omitempty"`
}

// UnmarshalJSON is only used for unit tests (to test MarshalJSON).
func (c *ClientRegistrationResponse) UnmarshalJSON(data []byte) error {
	// Step 1: Parse raw JSON to separate ClientRegistrationResponse-specific fields
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Step 2: Extract ClientRegistrationResponse-specific fields if present
	if ssRaw, ok := rawMap["registration_access_token"]; ok {
		if err := json.Unmarshal(ssRaw, &c.RegistrationAccessToken); err != nil {
			return err
		}
		delete(rawMap, "registration_access_token") // Remove to avoid duplication
	}

	if ssRaw, ok := rawMap["registration_client_uri"]; ok {
		if err := json.Unmarshal(ssRaw, &c.RegistrationClientURI); err != nil {
			return err
		}
		delete(rawMap, "registration_client_uri") // Remove to avoid duplication
	}

	// Step 3: Marshal remaining fields and unmarshal into ClientMetadata
	remainingData, err := json.Marshal(rawMap)
	if err != nil {
		return err
	}
	return json.Unmarshal(remainingData, &c.ClientInformationResponse)
}

func (c ClientRegistrationResponse) MarshalJSON() ([]byte, error) {
	// Marshal embedded ClientInformationResponse (includes custom logic)
	metaJSON, err := json.Marshal(c.ClientInformationResponse)
	if err != nil {
		return nil, err
	}

	// Convert to map to merge fields
	var combined map[string]interface{}
	if err := json.Unmarshal(metaJSON, &combined); err != nil {
		return nil, err
	}

	// Add ClientRegistrationResponse-specific fields
	if c.RegistrationAccessToken != "" {
		combined["registration_access_token"] = c.RegistrationAccessToken
	}
	if c.RegistrationClientURI != "" {
		combined["registration_client_uri"] = c.RegistrationClientURI
	}

	return json.Marshal(combined)
}

// ClientInformationErrorResponse implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1,
// 3.2.1. Client Information Response,
// https://www.rfc-editor.org/rfc/rfc7592.html#section-3
// 3. Client Information Response, and
// https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError
// 3.3.  Client Registration Error Response.
type ClientInformationErrorResponse struct {
	// Error is a single ASCII error code string.
	//
	// REQUIRED.
	Error ClientInformationErrorResponseErrorCode `json:"error"`

	// ErrorDescription is a human-readable ASCII text description of the error used for debugging.
	//
	// OPTIONAL.
	ErrorDescription string `json:"error_description,omitempty"`
}

const (
	// ClientInformationErrorResponseErrorCodeInvalidRedirectURI indicates that
	// the value of one or more redirection URIs is invalid.
	ClientInformationErrorResponseErrorCodeInvalidRedirectURI ClientInformationErrorResponseErrorCode = "invalid_redirect_uri"

	// ClientInformationErrorResponseErrorCodeInvalidClientMetadata indicates that
	// the value of one of the client metadata fields is invalid and the server has rejected this request.
	ClientInformationErrorResponseErrorCodeInvalidClientMetadata ClientInformationErrorResponseErrorCode = "invalid_client_metadata"

	// ClientInformationErrorResponseErrorCodeInvalidSoftwareStatement indicates that
	// the software statement presented is invalid.
	ClientInformationErrorResponseErrorCodeInvalidSoftwareStatement ClientInformationErrorResponseErrorCode = "invalid_software_statement"

	// ClientInformationErrorResponseErrorCodeUnapprovedSoftwareStatement indicates that
	// the software statement presented is not approved for use by this authorization server.
	ClientInformationErrorResponseErrorCodeUnapprovedSoftwareStatement ClientInformationErrorResponseErrorCode = "unapproved_software_statement"
)

type ClientInformationErrorResponseErrorCode string

// ClientReadResponse implements
// https://openid.net/specs/openid-connect-registration-1_0.html#ReadResponse
// 4.3.  Client Read Response.
//
// The Authorization Server need not include the registration_access_token or registration_client_uri value in this
// response unless they have been updated.
type ClientReadResponse struct {
	ClientRegistrationResponse
}

// ClientUpdateRequest implements https://www.rfc-editor.org/rfc/rfc7592.html#section-2.2
// 2.2 Client Update Request.
//
// Similar to ClientInformationResponse, except:
//
//	This request MUST include all client metadata fields as returned to
//	the client from a previous registration, read, or update operation.
//	The updated client metadata fields request MUST NOT include the
//	"registration_access_token", "registration_client_uri",
//	"client_secret_expires_at", or "client_id_issued_at" fields described
//	in Section 3.
type ClientUpdateRequest struct {
	ClientMetadata

	// ClientID is a OAuth 2.0 client identifier string.  It SHOULD NOT be
	// currently valid for any other registered client, though an
	// authorization server MAY issue the same client identifier to
	// multiple instances of a registered client at its discretion.
	//
	// REQUIRED.
	ClientID string `json:"client_id"`

	// ClientSecret is a OAuth 2.0 client secret string.  If issued, this MUST
	// be unique for each "client_id" and SHOULD be unique for multiple
	// instances of a client using the same "client_id".  This value is
	// used by confidential clients to authenticate to the token
	// endpoint, as described in OAuth 2.0 [RFC6749, Section 2.3.1].
	//
	// [RFC6749, Section 2.3.1]: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
	//
	// OPTIONAL.
	ClientSecret string `json:"client_secret,omitempty"`
}

func (c *ClientUpdateRequest) UnmarshalJSON(data []byte) error {
	// Step 1: Parse raw JSON to separate ClientUpdateRequest-specific fields
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}

	// Step 2: Extract ClientUpdateRequest-specific fields if present
	if ssRaw, ok := rawMap["client_id"]; ok {
		if err := json.Unmarshal(ssRaw, &c.ClientID); err != nil {
			return err
		}
		delete(rawMap, "client_id") // Remove to avoid duplication
	}

	if ssRaw, ok := rawMap["client_secret"]; ok {
		if err := json.Unmarshal(ssRaw, &c.ClientSecret); err != nil {
			return err
		}
		delete(rawMap, "client_secret") // Remove to avoid duplication
	}

	// Step 3: Marshal remaining fields and unmarshal into ClientMetadata
	remainingData, err := json.Marshal(rawMap)
	if err != nil {
		return err
	}
	return json.Unmarshal(remainingData, &c.ClientMetadata)
}

// ClientReadRequest implements
// https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1
// 2.1 Client Read Request.
type ClientReadRequest struct {
	ClientID string
}

// ClientDeleteRequest implements
// https://www.rfc-editor.org/rfc/rfc7592.html#section-2.3
// 2.3 Client Delete Request.
type ClientDeleteRequest struct {
	ClientID string
}
