package oidc

import (
	"github.com/go-jose/go-jose/v4"
)

// ClientRegistrationRequest implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.1,
// 3.1 Client Registration Request.
//
// Can also be used for https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1
// 2.2 Client Update Request.
//
// TODO: handle BCP 47
type ClientRegistrationRequest struct {
	RedirectURIs            []string           `json:"redirect_uris"`              // Array of redirection URI strings for use in redirect-based flows such as the authorization code and implicit flows.
	TokenEndpointAuthMethod AuthMethod         `json:"token_endpoint_auth_method"` // String indicator of the requested authentication method for the token endpoint.
	GrantTypes              []GrantType        `json:"grant_types"`                // Array of OAuth 2.0 grant type strings that the client can use at the token endpoint.
	ResponseTypes           []ResponseType     `json:"response_types"`             // Array of the OAuth 2.0 response type strings that the client can use at the authorization endpoint.
	ClientName              string             `json:"client_name"`                // Human-readable string name of the client to be presented to the end-user during authorization. (BCP 47)
	ClientURI               string             `json:"client_uri"`                 // URL string of a web page providing information about the client. (BCP 47)
	LogoURI                 string             `json:"logo_uri"`                   // URL string that references a logo for the client. (BCP 47)
	Scope                   string             `json:"scope"`                      // String containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use when requesting access tokens.
	Contacts                []string           `json:"contacts"`                   // Array of strings representing ways to contact people responsible for this client, typically email addresses.
	TOSURI                  string             `json:"tos_uri"`                    // URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client. (BCP 47)
	PolicyURI               string             `json:"policy_uri"`                 // URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data.
	JWKSURI                 string             `json:"jwks_uri"`                   // URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's public keys.
	JWKS                    jose.JSONWebKeySet `json:"jwks"`                       // Client's JSON Web Key Set [RFC7517] document value, which contains the client's public keys.
	SoftwareID              string             `json:"software_id"`                // A unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer or software publisher used by registration endpoints to identify the client software to be dynamically registered.
	SoftwareVersion         string             `json:"software_version"`           // A version identifier string for the client software identified by "software_id".
}

// ClientInformationResponse implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1,
// 3.2.1. Client Information Response and
// https://www.rfc-editor.org/rfc/rfc7592.html#section-3
// 3. Client Information Response.
type ClientInformationResponse struct {
	ClientID              string `json:"client_id"`                          // OAuth 2.0 client identifier string.
	ClientSecret          string `json:"client_secret,omitempty"`            // OAuth 2.0 client secret string.
	ClientIDIssuedAt      int64  `json:"client_id_issued_at,omitempty"`      // Time at which the client identifier was issued.
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"` // Time at which the client secret will expire or 0 if it will not expire.

	// fields that are reused from ClientRegistrationRequest
	RedirectURIs            []string           `json:"redirect_uris,omitempty"`              // Array of redirection URI strings for use in redirect-based flows such as the authorization code and implicit flows.
	TokenEndpointAuthMethod AuthMethod         `json:"token_endpoint_auth_method,omitempty"` // String indicator of the requested authentication method for the token endpoint.
	GrantTypes              []GrantType        `json:"grant_types,omitempty"`                // Array of OAuth 2.0 grant type strings that the client can use at the token endpoint.
	ResponseTypes           []ResponseType     `json:"response_types,omitempty"`             // Array of the OAuth 2.0 response type strings that the client can use at the authorization endpoint.
	ClientName              string             `json:"client_name,omitempty"`                // Human-readable string name of the client to be presented to the end-user during authorization. (BCP 47)
	ClientURI               string             `json:"client_uri,omitempty"`                 // URL string of a web page providing information about the client. (BCP 47)
	LogoURI                 string             `json:"logo_uri,omitempty"`                   // URL string that references a logo for the client. (BCP 47)
	Scope                   string             `json:"scope,omitempty"`                      // String containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use when requesting access tokens.
	Contacts                []string           `json:"contacts,omitempty"`                   // Array of strings representing ways to contact people responsible for this client, typically email addresses.
	TOSURI                  string             `json:"tos_uri,omitempty"`                    // URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client. (BCP 47)
	PolicyURI               string             `json:"policy_uri,omitempty"`                 // URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data. (BCP 47)
	JWKSURI                 string             `json:"jwks_uri,omitempty"`                   // URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's public keys.
	JWKS                    jose.JSONWebKeySet `json:"jwks,omitempty"`                       // Client's JSON Web Key Set [RFC7517] document value, which contains the client's public keys.
	SoftwareID              string             `json:"software_id,omitempty"`                // A unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer or software publisher used by registration endpoints to identify the client software to be dynamically registered.
	SoftwareVersion         string             `json:"software_version,omitempty"`           // A version identifier string for the client software identified by "software_id".
}

// ClientInformationErrorResponse implements
// https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1,
// 3.2.1. Client Information Response and
// https://www.rfc-editor.org/rfc/rfc7592.html#section-3
// 3. Client Information Response.
type ClientInformationErrorResponse struct {
	Error            ClientInformationErrorResponseErrorCode `json:"error"`                       // Single ASCII error code string.
	ErrorDescription string                                  `json:"error_description,omitempty"` // Human-readable ASCII text description of the error used for debugging.
}

const (
	ClientInformationErrorResponseErrorCodeInvalidRedirectURI          ClientInformationErrorResponseErrorCode = "invalid_redirect_uri"          // The value of one or more redirection URIs is invalid.
	ClientInformationErrorResponseErrorCodeInvalidClientMetadata       ClientInformationErrorResponseErrorCode = "invalid_client_metadata"       // The value of one of the client metadata fields is invalid and the server has rejected this request.
	ClientInformationErrorResponseErrorCodeInvalidSoftwareStatement    ClientInformationErrorResponseErrorCode = "invalid_software_statement"    // The software statement presented is invalid.
	ClientInformationErrorResponseErrorCodeUnapprovedSoftwareStatement ClientInformationErrorResponseErrorCode = "unapproved_software_statement" // The software statement presented is not approved for use by this authorization server.
)

type ClientInformationErrorResponseErrorCode string

// ClientUpdateRequest implements https://www.rfc-editor.org/rfc/rfc7592.html#section-2.1
// 2.2 Client Update Request.
//
// TODO: handle BCP 47
type ClientUpdateRequest struct {
	ClientID string `json:"client_id"`
	ClientRegistrationRequest
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
