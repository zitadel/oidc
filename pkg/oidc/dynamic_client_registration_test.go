package oidc

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClientRegistrationRequest(t *testing.T) {
	t.Run("unmarshal example from https://www.rfc-editor.org/rfc/rfc7591#page-17", func(t *testing.T) {
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
	})
	t.Run("unmarshal example from https://www.rfc-editor.org/rfc/rfc7591#page-18", func(t *testing.T) {
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
			"n": "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
				HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
				lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
				RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
				2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
				qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
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
	t.Run("unmarshal example from https://www.rfc-editor.org/rfc/rfc7591#page-19", func(t *testing.T) {
		marshalled := []byte(`
{
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2"
    ],
    "software_statement": "eyJhbGciOiJSUzI1NiJ9.
        eyJzb2Z0d2FyZV9pZCI6IjROUkIxLTBYWkFCWkk5RTYtNVNNM1IiLCJjbGll
        bnRfbmFtZSI6IkV4YW1wbGUgU3RhdGVtZW50LWJhc2VkIENsaWVudCIsImNs
        aWVudF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm5ldC8ifQ.
        GHfL4QNIrQwL18BSRdE595T9jbzqa06R9BT8w409x9oIcKaZo_mt15riEXHa
        zdISUvDIZhtiyNrSHQ8K4TvqWxH6uJgcmoodZdPwmWRIEYbQDLqPNxREtYn0
        5X3AR7ia4FRjQ2ojZjk5fJqJdQ-JcfxyhK-P8BAWBd6I2LLA77IG32xtbhxY
        fHX7VhuU5ProJO8uvu3Ayv4XRhLZJY4yKfmyjiiKiPNe-Ia4SMy_d_QSWxsk
        U5XIQl5Sa2YRPMbDRXttm2TfnZM1xx70DoYi8g6czz-CPGRi4SW_S2RKHIJf
        IjoI3zTJ0Y2oe0_EJAiXbL6OyF9S5tKxDXV8JIndSA",
    "scope": "read write",
    "example_extension_parameter": "example_value"
}
`)
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
	})
}
