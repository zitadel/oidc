package oidc

import (
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"strings"
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
	ClientName              map[string]string  `json:"client_name"`                // Human-readable string name of the client to be presented to the end-user during authorization. (BCP 47)
	ClientURI               map[string]string  `json:"client_uri"`                 // URL string of a web page providing information about the client. (BCP 47)
	LogoURI                 map[string]string  `json:"logo_uri"`                   // URL string that references a logo for the client. (BCP 47)
	Scope                   string             `json:"scope"`                      // String containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use when requesting access tokens.
	Contacts                []string           `json:"contacts"`                   // Array of strings representing ways to contact people responsible for this client, typically email addresses.
	TOSURI                  map[string]string  `json:"tos_uri"`                    // URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client. (BCP 47)
	PolicyURI               map[string]string  `json:"policy_uri"`                 // URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data. (BCP 47)
	JWKSURI                 string             `json:"jwks_uri"`                   // URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's public keys.
	JWKS                    jose.JSONWebKeySet `json:"jwks"`                       // Client's JSON Web Key Set [RFC7517] document value, which contains the client's public keys.
	SoftwareID              string             `json:"software_id"`                // A unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer or software publisher used by registration endpoints to identify the client software to be dynamically registered.
	SoftwareVersion         string             `json:"software_version"`           // A version identifier string for the client software identified by "software_id".
	SoftwareStatement       string             `json:"software_statement"`         // A software statement containing client metadata values about the client software as claims.

	// ExtraParameters holds other extension parameters.
	ExtraParameters map[string]interface{}
}

func (c *ClientRegistrationRequest) UnmarshalJSON(data []byte) error {
	// Initialize maps to avoid nil pointer issues later.
	c.ClientName = make(map[string]string)
	c.ClientURI = make(map[string]string)
	c.LogoURI = make(map[string]string)
	c.TOSURI = make(map[string]string)
	c.PolicyURI = make(map[string]string)
	c.ExtraParameters = make(map[string]interface{})

	// Unmarshal into a temporary map to inspect all keys.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("could not unmarshal raw data: %w", err)
	}

	// Iterate over all keys found in the JSON.
	for key, value := range raw {
		switch {
		case key == "redirect_uris":
			if uris, ok := value.([]interface{}); ok {
				for _, u := range uris {
					if uriStr, ok := u.(string); ok {
						c.RedirectURIs = append(c.RedirectURIs, uriStr)
					}
				}
			}
		case key == "token_endpoint_auth_method":
			if vStr, ok := value.(string); ok {
				if v, exists := AuthMethodMap[vStr]; exists {
					c.TokenEndpointAuthMethod = v
				}
			}
		case key == "grant_types":
			if gts, ok := value.([]interface{}); ok {
				for _, gt := range gts {
					if gtStr, ok := gt.(string); ok {
						if gtParsed, exists := GrantTypeMap[gtStr]; exists {
							c.GrantTypes = append(c.GrantTypes, gtParsed)
						}
					}
				}
			}
		case key == "response_types":
			if rts, ok := value.([]interface{}); ok {
				for _, rt := range rts {
					if rtStr, ok := rt.(string); ok {
						if rtParsed, exists := ResponseTypeMap[rtStr]; exists {
							c.ResponseTypes = append(c.ResponseTypes, rtParsed)
						}
					}
				}
			}
		case key == "client_name":
			if name, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.ClientName["default"] = name
			}
		case strings.HasPrefix(key, "client_name#"):
			if name, ok := value.(string); ok {
				// This is a tagged name, e.g., "client_name#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.ClientName[langTag] = name
				}
			}
		case key == "client_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.ClientURI["default"] = uri
			}
		case strings.HasPrefix(key, "client_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "client_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.ClientURI[langTag] = uri
				}
			}
		case key == "logo_uri":
			if logo, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.LogoURI["default"] = logo
			}
		case strings.HasPrefix(key, "logo_uri#"):
			if logo, ok := value.(string); ok {
				// This is a tagged name, e.g., "logo_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.LogoURI[langTag] = logo
				}
			}
		case key == "scope":
			if v, ok := value.(string); ok {
				c.Scope = v
			}
		case key == "contacts":
			if cts, ok := value.([]interface{}); ok {
				for _, ct := range cts {
					if ctStr, ok := ct.(string); ok {
						c.Contacts = append(c.Contacts, ctStr)
					}
				}
			}
		case key == "tos_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.TOSURI["default"] = uri
			}
		case strings.HasPrefix(key, "tos_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "tos_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.TOSURI[langTag] = uri
				}
			}
		case key == "policy_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.PolicyURI["default"] = uri
			}
		case strings.HasPrefix(key, "policy_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "policy_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.PolicyURI[langTag] = uri
				}
			}
		case key == "jwks_uri":
			if v, ok := value.(string); ok {
				c.JWKSURI = v
			}
		case key == "jwks":
			// unmarshal into a jose.JSONWebKeySet
			if vBytes, err := json.Marshal(value); err == nil {
				_ = json.Unmarshal(vBytes, &c.JWKS)
			}
		case key == "software_id":
			if v, ok := value.(string); ok {
				c.SoftwareID = v
			}
		case key == "software_version":
			if v, ok := value.(string); ok {
				c.SoftwareVersion = v
			}
		case key == "software_statement":
			if v, ok := value.(string); ok {
				c.SoftwareStatement = v
			}
		default:
			// If the key didn't match any of the above, it's an extra parameter.
			c.ExtraParameters[key] = value
		}
	}

	return nil
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
	ClientName              map[string]string  `json:"client_name,omitempty"`                // Human-readable string name of the client to be presented to the end-user during authorization. (BCP 47)
	ClientURI               map[string]string  `json:"client_uri,omitempty"`                 // URL string of a web page providing information about the client. (BCP 47)
	LogoURI                 map[string]string  `json:"logo_uri,omitempty"`                   // URL string that references a logo for the client. (BCP 47)
	Scope                   string             `json:"scope,omitempty"`                      // String containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use when requesting access tokens.
	Contacts                []string           `json:"contacts,omitempty"`                   // Array of strings representing ways to contact people responsible for this client, typically email addresses.
	TOSURI                  map[string]string  `json:"tos_uri,omitempty"`                    // URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client. (BCP 47)
	PolicyURI               map[string]string  `json:"policy_uri,omitempty"`                 // URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data. (BCP 47)
	JWKSURI                 string             `json:"jwks_uri,omitempty"`                   // URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's public keys.
	JWKS                    jose.JSONWebKeySet `json:"jwks,omitempty"`                       // Client's JSON Web Key Set [RFC7517] document value, which contains the client's public keys.
	SoftwareID              string             `json:"software_id,omitempty"`                // A unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer or software publisher used by registration endpoints to identify the client software to be dynamically registered.
	SoftwareVersion         string             `json:"software_version,omitempty"`           // A version identifier string for the client software identified by "software_id".
	RegistrationAccessToken string             `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string             `json:"registration_client_uri,omitempty"`

	// ExtraParameters holds other extension parameters.
	ExtraParameters map[string]interface{}
}

func (c ClientInformationResponse) MarshalJSON() ([]byte, error) {
	res := make(map[string]interface{})

	res["client_id"] = c.ClientID // always present
	if c.ClientSecret != "" {
		res["client_secret"] = c.ClientSecret
	}
	if c.ClientIDIssuedAt != 0 {
		res["client_id_issued_at"] = c.ClientIDIssuedAt
	}
	if c.ClientSecretExpiresAt != 0 {
		res["client_secret_expires_at"] = c.ClientSecretExpiresAt
	}

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
	if len(c.ClientName) > 0 {
		for lang, name := range c.ClientName {
			if lang == "default" {
				res["client_name"] = name
			} else {
				res[fmt.Sprintf("client_name#%s", lang)] = name
			}
		}
	}
	if len(c.ClientURI) > 0 {
		for lang, uri := range c.ClientURI {
			if lang == "default" {
				res["client_uri"] = uri
			} else {
				res[fmt.Sprintf("client_uri#%s", lang)] = uri
			}
		}
	}
	if len(c.LogoURI) > 0 {
		for lang, logo := range c.LogoURI {
			if lang == "default" {
				res["logo_uri"] = logo
			} else {
				res[fmt.Sprintf("logo_uri#%s", lang)] = logo
			}
		}
	}
	if c.Scope != "" {
		res["scope"] = c.Scope
	}
	if len(c.Contacts) > 0 {
		res["contacts"] = c.Contacts
	}
	if len(c.TOSURI) > 0 {
		for lang, uri := range c.TOSURI {
			if lang == "default" {
				res["tos_uri"] = uri
			} else {
				res[fmt.Sprintf("tos_uri#%s", lang)] = uri
			}
		}
	}
	if len(c.PolicyURI) > 0 {
		for lang, uri := range c.PolicyURI {
			if lang == "default" {
				res["policy_uri"] = uri
			} else {
				res[fmt.Sprintf("policy_uri#%s", lang)] = uri
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
	if c.RegistrationAccessToken != "" {
		res["registration_access_token"] = c.RegistrationAccessToken
	}
	if c.RegistrationClientURI != "" {
		res["registration_client_uri"] = c.RegistrationClientURI
	}

	// Add extra parameters
	for key, value := range c.ExtraParameters {
		res[key] = value
	}

	return json.Marshal(res)
}
func (c *ClientInformationResponse) UnmarshalJSON(data []byte) error {
	// Initialize maps to avoid nil pointer issues later.
	c.ClientName = make(map[string]string)
	c.ClientURI = make(map[string]string)
	c.LogoURI = make(map[string]string)
	c.TOSURI = make(map[string]string)
	c.PolicyURI = make(map[string]string)
	c.ExtraParameters = make(map[string]interface{})

	// Unmarshal into a temporary map to inspect all keys.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("could not unmarshal raw data: %w", err)
	}

	// Iterate over all keys found in the JSON.
	for key, value := range raw {
		switch {
		case key == "client_id":
			if v, ok := value.(string); ok {
				c.ClientID = v
			}
		case key == "client_secret":
			if v, ok := value.(string); ok {
				c.ClientSecret = v
			}
		case key == "client_id_issued_at":
			if v, ok := value.(float64); ok {
				c.ClientIDIssuedAt = int64(v)
			}
		case key == "client_secret_expires_at":
			if v, ok := value.(float64); ok {
				c.ClientSecretExpiresAt = int64(v)
			}
		case key == "redirect_uris":
			if uris, ok := value.([]interface{}); ok {
				for _, u := range uris {
					if uriStr, ok := u.(string); ok {
						c.RedirectURIs = append(c.RedirectURIs, uriStr)
					}
				}
			}
		case key == "token_endpoint_auth_method":
			if vStr, ok := value.(string); ok {
				if v, exists := AuthMethodMap[vStr]; exists {
					c.TokenEndpointAuthMethod = v
				}
			}
		case key == "grant_types":
			if gts, ok := value.([]interface{}); ok {
				for _, gt := range gts {
					if gtStr, ok := gt.(string); ok {
						if gtParsed, exists := GrantTypeMap[gtStr]; exists {
							c.GrantTypes = append(c.GrantTypes, gtParsed)
						}
					}
				}
			}
		case key == "response_types":
			if rts, ok := value.([]interface{}); ok {
				for _, rt := range rts {
					if rtStr, ok := rt.(string); ok {
						if rtParsed, exists := ResponseTypeMap[rtStr]; exists {
							c.ResponseTypes = append(c.ResponseTypes, rtParsed)
						}
					}
				}
			}
		case key == "client_name":
			if name, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.ClientName["default"] = name
			}
		case strings.HasPrefix(key, "client_name#"):
			if name, ok := value.(string); ok {
				// This is a tagged name, e.g., "client_name#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.ClientName[langTag] = name
				}
			}
		case key == "client_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.ClientURI["default"] = uri
			}
		case strings.HasPrefix(key, "client_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "client_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.ClientURI[langTag] = uri
				}
			}
		case key == "logo_uri":
			if logo, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.LogoURI["default"] = logo
			}
		case strings.HasPrefix(key, "logo_uri#"):
			if logo, ok := value.(string); ok {
				// This is a tagged name, e.g., "logo_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.LogoURI[langTag] = logo
				}
			}
		case key == "scope":
			if v, ok := value.(string); ok {
				c.Scope = v
			}
		case key == "contacts":
			if cts, ok := value.([]interface{}); ok {
				for _, ct := range cts {
					if ctStr, ok := ct.(string); ok {
						c.Contacts = append(c.Contacts, ctStr)
					}
				}
			}
		case key == "tos_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.TOSURI["default"] = uri
			}
		case strings.HasPrefix(key, "tos_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "tos_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.TOSURI[langTag] = uri
				}
			}
		case key == "policy_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.PolicyURI["default"] = uri
			}
		case strings.HasPrefix(key, "policy_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "policy_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.PolicyURI[langTag] = uri
				}
			}
		case key == "jwks_uri":
			if v, ok := value.(string); ok {
				c.JWKSURI = v
			}
		case key == "jwks":
			if v, ok := value.(jose.JSONWebKeySet); ok {
				c.JWKS = v
			}
		case key == "software_id":
			if v, ok := value.(string); ok {
				c.SoftwareID = v
			}
		case key == "software_version":
			if v, ok := value.(string); ok {
				c.SoftwareVersion = v
			}
		case key == "registration_access_token":
			if v, ok := value.(string); ok {
				c.RegistrationAccessToken = v
			}
		case key == "registration_client_uri":
			if v, ok := value.(string); ok {
				c.RegistrationClientURI = v
			}
		default:
			// If the key didn't match any of the above, it's an extra parameter.
			c.ExtraParameters[key] = value
		}
	}

	return nil
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
// Similar to ClientInformationResponse, except:
//
//		This request MUST include all client metadata fields as returned to
//	  the client from a previous registration, read, or update operation.
//	  The updated client metadata fields request MUST NOT include the
//	  "registration_access_token", "registration_client_uri",
//	  "client_secret_expires_at", or "client_id_issued_at" fields described
//	  in Section 3.
type ClientUpdateRequest struct {
	ClientID     string `json:"client_id"`               // OAuth 2.0 client identifier string.
	ClientSecret string `json:"client_secret,omitempty"` // OAuth 2.0 client secret string.
	//ClientIDIssuedAt      int64  `json:"client_id_issued_at,omitempty"`      // Time at which the client identifier was issued.
	//ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"` // Time at which the client secret will expire or 0 if it will not expire.

	// fields that are reused from ClientRegistrationRequest
	RedirectURIs            []string           `json:"redirect_uris,omitempty"`              // Array of redirection URI strings for use in redirect-based flows such as the authorization code and implicit flows.
	TokenEndpointAuthMethod AuthMethod         `json:"token_endpoint_auth_method,omitempty"` // String indicator of the requested authentication method for the token endpoint.
	GrantTypes              []GrantType        `json:"grant_types,omitempty"`                // Array of OAuth 2.0 grant type strings that the client can use at the token endpoint.
	ResponseTypes           []ResponseType     `json:"response_types,omitempty"`             // Array of the OAuth 2.0 response type strings that the client can use at the authorization endpoint.
	ClientName              map[string]string  `json:"client_name,omitempty"`                // Human-readable string name of the client to be presented to the end-user during authorization. (BCP 47)
	ClientURI               map[string]string  `json:"client_uri,omitempty"`                 // URL string of a web page providing information about the client. (BCP 47)
	LogoURI                 map[string]string  `json:"logo_uri,omitempty"`                   // URL string that references a logo for the client. (BCP 47)
	Scope                   string             `json:"scope,omitempty"`                      // String containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use when requesting access tokens.
	Contacts                []string           `json:"contacts,omitempty"`                   // Array of strings representing ways to contact people responsible for this client, typically email addresses.
	TOSURI                  map[string]string  `json:"tos_uri,omitempty"`                    // URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client. (BCP 47)
	PolicyURI               map[string]string  `json:"policy_uri,omitempty"`                 // URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data. (BCP 47)
	JWKSURI                 string             `json:"jwks_uri,omitempty"`                   // URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document, which contains the client's public keys.
	JWKS                    jose.JSONWebKeySet `json:"jwks,omitempty"`                       // Client's JSON Web Key Set [RFC7517] document value, which contains the client's public keys.
	SoftwareID              string             `json:"software_id,omitempty"`                // A unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer or software publisher used by registration endpoints to identify the client software to be dynamically registered.
	SoftwareVersion         string             `json:"software_version,omitempty"`           // A version identifier string for the client software identified by "software_id".
	//RegistrationAccessToken string             `json:"registration_access_token,omitempty"`
	//RegistrationClientURI   string             `json:"registration_client_uri,omitempty"`

	// ExtraParameters holds other extension parameters.
	ExtraParameters map[string]interface{}
}

// UnmarshalJSON
//
// TODO: collapse with ClientInformationResponse.UnmarshalJSON
func (c *ClientUpdateRequest) UnmarshalJSON(data []byte) error {
	// Initialize maps to avoid nil pointer issues later.
	c.ClientName = make(map[string]string)
	c.ClientURI = make(map[string]string)
	c.LogoURI = make(map[string]string)
	c.TOSURI = make(map[string]string)
	c.PolicyURI = make(map[string]string)
	c.ExtraParameters = make(map[string]interface{})

	// Unmarshal into a temporary map to inspect all keys.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("could not unmarshal raw data: %w", err)
	}

	// Iterate over all keys found in the JSON.
	for key, value := range raw {
		switch {
		case key == "client_id":
			if v, ok := value.(string); ok {
				c.ClientID = v
			}
		case key == "client_secret":
			if v, ok := value.(string); ok {
				c.ClientSecret = v
			}
		case key == "redirect_uris":
			if uris, ok := value.([]interface{}); ok {
				for _, u := range uris {
					if uriStr, ok := u.(string); ok {
						c.RedirectURIs = append(c.RedirectURIs, uriStr)
					}
				}
			}
		case key == "token_endpoint_auth_method":
			if vStr, ok := value.(string); ok {
				if v, exists := AuthMethodMap[vStr]; exists {
					c.TokenEndpointAuthMethod = v
				}
			}
		case key == "grant_types":
			if gts, ok := value.([]interface{}); ok {
				for _, gt := range gts {
					if gtStr, ok := gt.(string); ok {
						if gtParsed, exists := GrantTypeMap[gtStr]; exists {
							c.GrantTypes = append(c.GrantTypes, gtParsed)
						}
					}
				}
			}
		case key == "response_types":
			if rts, ok := value.([]interface{}); ok {
				for _, rt := range rts {
					if rtStr, ok := rt.(string); ok {
						if rtParsed, exists := ResponseTypeMap[rtStr]; exists {
							c.ResponseTypes = append(c.ResponseTypes, rtParsed)
						}
					}
				}
			}
		case key == "client_name":
			if name, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.ClientName["default"] = name
			}
		case strings.HasPrefix(key, "client_name#"):
			if name, ok := value.(string); ok {
				// This is a tagged name, e.g., "client_name#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.ClientName[langTag] = name
				}
			}
		case key == "client_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.ClientURI["default"] = uri
			}
		case strings.HasPrefix(key, "client_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "client_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.ClientURI[langTag] = uri
				}
			}
		case key == "logo_uri":
			if logo, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.LogoURI["default"] = logo
			}
		case strings.HasPrefix(key, "logo_uri#"):
			if logo, ok := value.(string); ok {
				// This is a tagged name, e.g., "logo_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.LogoURI[langTag] = logo
				}
			}
		case key == "scope":
			if v, ok := value.(string); ok {
				c.Scope = v
			}
		case key == "contacts":
			if cts, ok := value.([]interface{}); ok {
				for _, ct := range cts {
					if ctStr, ok := ct.(string); ok {
						c.Contacts = append(c.Contacts, ctStr)
					}
				}
			}
		case key == "tos_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.TOSURI["default"] = uri
			}
		case strings.HasPrefix(key, "tos_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "tos_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.TOSURI[langTag] = uri
				}
			}
		case key == "policy_uri":
			if uri, ok := value.(string); ok {
				// This is the default, non-tagged name.
				c.PolicyURI["default"] = uri
			}
		case strings.HasPrefix(key, "policy_uri#"):
			if uri, ok := value.(string); ok {
				// This is a tagged name, e.g., "policy_uri#ja-Jpan-JP"
				// Split the key at the first '#' to get the language tag.
				parts := strings.SplitN(key, "#", 2)
				if len(parts) == 2 {
					langTag := parts[1]
					c.PolicyURI[langTag] = uri
				}
			}
		case key == "jwks_uri":
			if v, ok := value.(string); ok {
				c.JWKSURI = v
			}
		case key == "jwks":
			if v, ok := value.(jose.JSONWebKeySet); ok {
				c.JWKS = v
			}
		case key == "software_id":
			if v, ok := value.(string); ok {
				c.SoftwareID = v
			}
		case key == "software_version":
			if v, ok := value.(string); ok {
				c.SoftwareVersion = v
			}
		default:
			// If the key didn't match any of the above, it's an extra parameter.
			c.ExtraParameters[key] = value
		}
	}

	return nil
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
