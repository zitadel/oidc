package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func compareRSAJSONWebKey(
	t *testing.T,
	wantEStr, wantNStr string,
	gotJWKS jose.JSONWebKey,
) {
	t.Helper()

	eBytes, err := base64.RawURLEncoding.DecodeString(wantEStr)
	require.NoError(t, err)
	nBytes, err := base64.RawURLEncoding.DecodeString(wantNStr)
	require.NoError(t, err)
	e := new(big.Int).SetBytes(eBytes).Int64()
	n := new(big.Int).SetBytes(nBytes)

	pubKey, ok := gotJWKS.Key.(*rsa.PublicKey)
	require.True(t, ok)

	assert.Equal(t, int(e), pubKey.E)
	assert.Equal(t, n, pubKey.N)
}

func TestClientRegistrationRequest(t *testing.T) {
	t.Run("test grant types", func(t *testing.T) {
		marshalled := []byte(`
{
	"grant_types": [
		"authorization_code", 
		"refresh_token", 
		"client_credentials",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:token-exchange",
		"implicit", 
		"urn:ietf:params:oauth:grant-type:device_code", 
		"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	]
}
`)
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Len(t, req.GrantTypes, 8)
		assert.Contains(t, req.GrantTypes, GrantTypeCode)
		assert.Contains(t, req.GrantTypes, GrantTypeRefreshToken)
		assert.Contains(t, req.GrantTypes, GrantTypeClientCredentials)
		assert.Contains(t, req.GrantTypes, GrantTypeBearer)
		assert.Contains(t, req.GrantTypes, GrantTypeTokenExchange)
		assert.Contains(t, req.GrantTypes, GrantTypeImplicit)
		assert.Contains(t, req.GrantTypes, GrantTypeDeviceCode)
		assert.Contains(t, req.GrantTypes, GrantType(ClientAssertionTypeJWTAssertion))
	})
	t.Run("test response types", func(t *testing.T) {
		marshalled := []byte(`
{
	"response_types": ["code", "id_token token", "id_token"]
}
`)
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Len(t, req.ResponseTypes, 3)
		assert.Contains(t, req.ResponseTypes, ResponseTypeCode)
		assert.Contains(t, req.ResponseTypes, ResponseTypeIDToken)
		assert.Contains(t, req.ResponseTypes, ResponseTypeIDTokenOnly)
	})
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-17
	t.Run("unmarshal Client Registration Request example", func(t *testing.T) {
		marshalled := []byte(`
{
	"redirect_uris": [
		"https://client.example.org/callback",
		"https://client.example.org/callback2"
	],
	"client_name": "My Example Client",
	"client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
	"token_endpoint_auth_method": "client_secret_basic",
	"logo_uri": "https://client.example.org/logo.png",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks",
	"example_extension_parameter": "example_value"
}
`)
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Len(t, req.RedirectURIs, 2)
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback2")
		assert.Len(t, req.ClientName, 2)
		assert.Equal(t, "My Example Client", req.ClientName["default"])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req.ClientName["ja-Jpan-JP"])
		assert.Equal(t, AuthMethodBasic, req.TokenEndpointAuthMethod)
		assert.Len(t, req.LogoURI, 1)
		assert.Equal(t, "https://client.example.org/logo.png", req.LogoURI["default"])
		assert.Equal(t, "https://client.example.org/my_public_keys.jwks", req.JWKSURI)
		assert.Contains(t, req.ExtraParameters, "example_extension_parameter")
		assert.Len(t, req.ExtraParameters, 1)
		assert.Contains(t, req.ExtraParameters, "example_extension_parameter")
		assert.Equal(t, "example_value", req.ExtraParameters["example_extension_parameter"])
	})
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-18
	t.Run("unmarshal Client Registration Request example", func(t *testing.T) {
		marshalled := []byte(`
{
    "redirect_uris": [
		"https://client.example.org/callback",
        "https://client.example.org/callback2"
	],
	"client_name": "My Example Client",
	"client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
	"token_endpoint_auth_method": "client_secret_basic",
	"policy_uri": "https://client.example.org/policy.html",
	"jwks": {
		"keys": [{
			"e": "AQAB",
			"n": "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyklBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70pRM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKveqXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
			"kty": "RSA"
		}]
	},
	"example_extension_parameter": "example_value"
}
`)
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Len(t, req.RedirectURIs, 2)
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback2")
		assert.Len(t, req.ClientName, 2)
		assert.Equal(t, "My Example Client", req.ClientName["default"])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req.ClientName["ja-Jpan-JP"])
		assert.Equal(t, AuthMethodBasic, req.TokenEndpointAuthMethod)
		assert.Len(t, req.PolicyURI, 1)
		assert.Equal(t, "https://client.example.org/policy.html", req.PolicyURI["default"])
		assert.Len(t, req.JWKS.Keys, 1)
		compareRSAJSONWebKey(
			t,
			"AQAB",
			"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfGHrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyklBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70pRM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKveqXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
			req.JWKS.Keys[0],
		)
		assert.Len(t, req.ExtraParameters, 1)
		assert.Contains(t, req.ExtraParameters, "example_extension_parameter")
		assert.Equal(t, "example_value", req.ExtraParameters["example_extension_parameter"])

	})
	// from https://www.rfc-editor.org/rfc/rfc7591#page-19
	t.Run("unmarshal Client Registration Request example", func(t *testing.T) {
		marshalled := []byte(`
{
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2"
    ],
    "software_statement": "eyJhbGciOiJSUzI1NiJ9.eyJzb2Z0d2FyZV9pZCI6IjROUkIxLTBYWkFCWkk5RTYtNVNNM1IiLCJjbGllbnRfbmFtZSI6IkV4YW1wbGUgU3RhdGVtZW50LWJhc2VkIENsaWVudCIsImNsaWVudF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm5ldC8ifQ.GHfL4QNIrQwL18BSRdE595T9jbzqa06R9BT8w409x9oIcKaZo_mt15riEXHazdISUvDIZhtiyNrSHQ8K4TvqWxH6uJgcmoodZdPwmWRIEYbQDLqPNxREtYn05X3AR7ia4FRjQ2ojZjk5fJqJdQ-JcfxyhK-P8BAWBd6I2LLA77IG32xtbhxYfHX7VhuU5ProJO8uvu3Ayv4XRhLZJY4yKfmyjiiKiPNe-Ia4SMy_d_QSWxskU5XIQl5Sa2YRPMbDRXttm2TfnZM1xx70DoYi8g6czz-CPGRi4SW_S2RKHIJfIjoI3zTJ0Y2oe0_EJAiXbL6OyF9S5tKxDXV8JIndSA",
    "scope": "read write",
    "example_extension_parameter": "example_value"
}
`)
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Len(t, req.RedirectURIs, 2)
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback2")
		assert.Equal(
			t,
			"eyJhbGciOiJSUzI1NiJ9.eyJzb2Z0d2FyZV9pZCI6IjROUkIxLTBYWkFCWkk5RTYtNVNNM1IiLCJjbGllbnRfbmFtZSI6IkV4YW1wbGUgU3RhdGVtZW50LWJhc2VkIENsaWVudCIsImNsaWVudF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm5ldC8ifQ.GHfL4QNIrQwL18BSRdE595T9jbzqa06R9BT8w409x9oIcKaZo_mt15riEXHazdISUvDIZhtiyNrSHQ8K4TvqWxH6uJgcmoodZdPwmWRIEYbQDLqPNxREtYn05X3AR7ia4FRjQ2ojZjk5fJqJdQ-JcfxyhK-P8BAWBd6I2LLA77IG32xtbhxYfHX7VhuU5ProJO8uvu3Ayv4XRhLZJY4yKfmyjiiKiPNe-Ia4SMy_d_QSWxskU5XIQl5Sa2YRPMbDRXttm2TfnZM1xx70DoYi8g6czz-CPGRi4SW_S2RKHIJfIjoI3zTJ0Y2oe0_EJAiXbL6OyF9S5tKxDXV8JIndSA",
			req.SoftwareStatement,
		)
		assert.Equal(t, "read write", req.Scope)
		assert.Len(t, req.ExtraParameters, 1)
		assert.Contains(t, req.ExtraParameters, "example_extension_parameter")
		assert.Equal(t, "example_value", req.ExtraParameters["example_extension_parameter"])
	})
}

func TestClientUpdateRequest(t *testing.T) {
	// from https://www.rfc-editor.org/rfc/rfc7592.html#page-8
	t.Run("unmarshal Client Update Request example", func(t *testing.T) {
		marshalled := []byte(`
{
	"client_id": "s6BhdRkqt3",
	"client_secret": "cf136dc3c1fc93f31185e5885805d",
	"redirect_uris": [
		"https://client.example.org/callback",
		"https://client.example.org/alt"
	],
	"grant_types": ["authorization_code", "refresh_token"],
	"token_endpoint_auth_method": "client_secret_basic",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks",
	"client_name": "My New Example",
	"client_name#fr": "Mon Nouvel Exemple",
	"logo_uri": "https://client.example.org/newlogo.png",
	"logo_uri#fr": "https://client.example.org/fr/newlogo.png"
}
`)
		var req ClientUpdateRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Equal(t, "s6BhdRkqt3", req.ClientID)
		assert.Equal(t, "cf136dc3c1fc93f31185e5885805d", req.ClientSecret)
		assert.Len(t, req.RedirectURIs, 2)
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/alt")
		assert.Len(t, req.GrantTypes, 2)
		assert.Contains(t, req.GrantTypes, GrantTypeCode)
		assert.Contains(t, req.GrantTypes, GrantTypeRefreshToken)
		assert.Equal(t, "https://client.example.org/my_public_keys.jwks", req.JWKSURI)
		assert.Equal(t, "My New Example", req.ClientName["default"])
		assert.Equal(t, "Mon Nouvel Exemple", req.ClientName["fr"])
		assert.Equal(t, "https://client.example.org/newlogo.png", req.LogoURI["default"])
		assert.Equal(t, "https://client.example.org/fr/newlogo.png", req.LogoURI["fr"])
	})
}

func TestClientInformationResponse(t *testing.T) {
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-21
	t.Run("unmarshal example", func(t *testing.T) {
		marshalled := []byte(`
{
	"client_id": "s6BhdRkqt3",
	"client_secret": "cf136dc3c1fc93f31185e5885805d",
	"client_id_issued_at": 2893256800,
	"client_secret_expires_at": 2893276800,
	"redirect_uris": [
		"https://client.example.org/callback",
		"https://client.example.org/callback2"
	],
	"grant_types": ["authorization_code", "refresh_token"],
	"client_name": "My Example Client",
	"client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
	"token_endpoint_auth_method": "client_secret_basic",
	"logo_uri": "https://client.example.org/logo.png",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks",
	"example_extension_parameter": "example_value"
}
`)
		var req ClientInformationResponse
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Equal(t, "s6BhdRkqt3", req.ClientID)
		assert.Equal(t, "cf136dc3c1fc93f31185e5885805d", req.ClientSecret)
		assert.Equal(t, int64(2893256800), req.ClientIDIssuedAt)
		assert.Equal(t, int64(2893276800), req.ClientSecretExpiresAt)
		assert.Len(t, req.RedirectURIs, 2)
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback2")
		assert.Len(t, req.GrantTypes, 2)
		assert.Contains(t, req.GrantTypes, GrantTypeCode)
		assert.Contains(t, req.GrantTypes, GrantTypeRefreshToken)
		assert.Len(t, req.ClientName, 2)
		assert.Equal(t, "My Example Client", req.ClientName["default"])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req.ClientName["ja-Jpan-JP"])
		assert.Equal(t, AuthMethodBasic, req.TokenEndpointAuthMethod)
		assert.Len(t, req.LogoURI, 1)
		assert.Equal(t, "https://client.example.org/logo.png", req.LogoURI["default"])
		assert.Equal(t, "https://client.example.org/my_public_keys.jwks", req.JWKSURI)
		assert.Len(t, req.ExtraParameters, 1)
		assert.Contains(t, req.ExtraParameters, "example_extension_parameter")
		assert.Equal(t, "example_value", req.ExtraParameters["example_extension_parameter"])
	})
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-21
	t.Run("unmarshal example, then marshal, unmarshal again", func(t *testing.T) {
		marshalled1 := []byte(`
{
	"client_id": "s6BhdRkqt3",
	"client_secret": "cf136dc3c1fc93f31185e5885805d",
	"client_id_issued_at": 2893256800,
	"client_secret_expires_at": 2893276800,
	"redirect_uris": [
		"https://client.example.org/callback",
		"https://client.example.org/callback2"
	],
	"grant_types": ["authorization_code", "refresh_token"],
	"client_name": "My Example Client",
	"client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
	"token_endpoint_auth_method": "client_secret_basic",
	"logo_uri": "https://client.example.org/logo.png",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks",
	"example_extension_parameter": "example_value"
}
`)
		var req1 ClientInformationResponse
		require.NoError(t, json.Unmarshal(marshalled1, &req1))

		marshalled2, err2 := json.Marshal(req1)
		require.NoError(t, err2)

		var req3 ClientInformationResponse
		require.NoError(t, json.Unmarshal(marshalled2, &req3))

		assert.Equal(t, "s6BhdRkqt3", req3.ClientID)
		assert.Equal(t, "cf136dc3c1fc93f31185e5885805d", req3.ClientSecret)
		assert.Equal(t, int64(2893256800), req3.ClientIDIssuedAt)
		assert.Equal(t, int64(2893276800), req3.ClientSecretExpiresAt)
		assert.Len(t, req3.RedirectURIs, 2)
		assert.Contains(t, req3.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req3.RedirectURIs, "https://client.example.org/callback2")
		assert.Len(t, req3.GrantTypes, 2)
		assert.Contains(t, req3.GrantTypes, GrantTypeCode)
		assert.Contains(t, req3.GrantTypes, GrantTypeRefreshToken)
		assert.Len(t, req3.ClientName, 2)
		assert.Equal(t, "My Example Client", req3.ClientName["default"])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req3.ClientName["ja-Jpan-JP"])
		assert.Equal(t, AuthMethodBasic, req3.TokenEndpointAuthMethod)
		assert.Len(t, req3.LogoURI, 1)
		assert.Equal(t, "https://client.example.org/logo.png", req3.LogoURI["default"])
		assert.Equal(t, "https://client.example.org/my_public_keys.jwks", req3.JWKSURI)
		assert.Len(t, req3.ExtraParameters, 1)
		assert.Contains(t, req3.ExtraParameters, "example_extension_parameter")
		assert.Equal(t, "example_value", req3.ExtraParameters["example_extension_parameter"])
	})

	// example from https://www.rfc-editor.org/rfc/rfc7592.html#page-11
	t.Run("unmarshal example, then marshal, unmarshal again", func(t *testing.T) {
		marshalled1 := []byte(`
{
	"registration_access_token": "reg-23410913-abewfq.123483",
	"registration_client_uri": "https://server.example.com/register/s6BhdRkqt3",
	"client_id": "s6BhdRkqt3",
	"client_secret": "cf136dc3c1fc93f31185e5885805d",
	"client_id_issued_at": 2893256800,
	"client_secret_expires_at": 2893276800,
	"client_name": "My Example Client",
	"client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
	"redirect_uris": [
		"https://client.example.org/callback",
		"https://client.example.org/callback2"
	],
	"grant_types": ["authorization_code", "refresh_token"],
	"token_endpoint_auth_method": "client_secret_basic",
	"logo_uri": "https://client.example.org/logo.png",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks"
}
`)
		var req ClientInformationResponse
		require.NoError(t, json.Unmarshal(marshalled1, &req))

		var req1 ClientInformationResponse
		require.NoError(t, json.Unmarshal(marshalled1, &req1))

		marshalled2, err2 := json.Marshal(req1)
		require.NoError(t, err2)

		var req3 ClientInformationResponse
		require.NoError(t, json.Unmarshal(marshalled2, &req3))

		assert.Equal(t, "reg-23410913-abewfq.123483", req3.RegistrationAccessToken)
		assert.Equal(t, "https://server.example.com/register/s6BhdRkqt3", req3.RegistrationClientURI)
		assert.Equal(t, "s6BhdRkqt3", req3.ClientID)
		assert.Equal(t, int64(2893256800), req3.ClientIDIssuedAt)
		assert.Equal(t, int64(2893276800), req3.ClientSecretExpiresAt)
		assert.Len(t, req3.ClientName, 2)
		assert.Equal(t, "My Example Client", req3.ClientName["default"])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req3.ClientName["ja-Jpan-JP"])
		assert.Len(t, req3.RedirectURIs, 2)
		assert.Contains(t, req3.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req3.RedirectURIs, "https://client.example.org/callback2")
		assert.Len(t, req3.GrantTypes, 2)
		assert.Contains(t, req3.GrantTypes, GrantTypeCode)
		assert.Contains(t, req3.GrantTypes, GrantTypeRefreshToken)
		assert.Len(t, req3.LogoURI, 1)
		assert.Equal(t, "https://client.example.org/logo.png", req3.LogoURI["default"])
		assert.Equal(t, "https://client.example.org/my_public_keys.jwks", req3.JWKSURI)
	})
}

func TestClientInformationErrorResponse(t *testing.T) {
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-23
	t.Run("unmarshal example", func(t *testing.T) {
		marshalled := []byte(`
{
	"error": "invalid_redirect_uri",
	"error_description": "The redirection URI http://sketchy.example.com is not allowed by this server."
}
`)
		var req ClientInformationErrorResponse
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Equal(t, ClientInformationErrorResponseErrorCodeInvalidRedirectURI, req.Error)
		assert.Equal(t, "The redirection URI http://sketchy.example.com is not allowed by this server.", req.ErrorDescription)
	})
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-23
	t.Run("unmarshal example", func(t *testing.T) {
		marshalled := []byte(`
{
	"error": "invalid_client_metadata",
	"error_description": "The grant type 'authorization_code' must be registered along with the response type 'code' but found only 'implicit' instead."
}
`)
		var req ClientInformationErrorResponse
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Equal(t, ClientInformationErrorResponseErrorCodeInvalidClientMetadata, req.Error)
		assert.Equal(t, "The grant type 'authorization_code' must be registered along with the response type 'code' but found only 'implicit' instead.", req.ErrorDescription)
	})
}
