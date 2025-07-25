package oidc

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClientRegistrationRequest(t *testing.T) {
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
	})
	// from https://www.rfc-editor.org/rfc/rfc7592.html#page-7
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
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
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
	})

	// example fromhttps://www.rfc-editor.org/rfc/rfc7592.html#page-11
	t.Run("unmarshal example", func(t *testing.T) {
		marshalled := []byte(`
{
	"registration_access_token": "reg-23410913-abewfq.123483",
	"registration_client_uri":
	 "https://server.example.com/register/s6BhdRkqt3",
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
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
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
