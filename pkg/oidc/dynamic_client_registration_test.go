package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/internationalizedfield"
	"golang.org/x/text/language"
	"math/big"
	"testing"
)

// compareRSAJSONWebKey is a test helper to compare a given jose.JSONWebKey with the
// equivalent base64-encoded RSA E and N values.
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
	wantJPTag, err := language.Parse("ja-Jpan-JP")
	require.NoError(t, err)
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
		assert.Len(t, req.ClientName.Entries, 2)
		assert.Equal(t, "My Example Client", req.ClientName.Entries[language.Und])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req.ClientName.Entries[wantJPTag])
		assert.Equal(t, AuthMethodBasic, req.TokenEndpointAuthMethod)
		assert.Len(t, req.LogoURI.Entries, 1)
		assert.Equal(t, "https://client.example.org/logo.png", req.LogoURI.Entries[language.Und])
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
		assert.Len(t, req.ClientName.Entries, 2)
		assert.Equal(t, "My Example Client", req.ClientName.Entries[language.Und])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req.ClientName.Entries[wantJPTag])
		assert.Equal(t, AuthMethodBasic, req.TokenEndpointAuthMethod)
		assert.Len(t, req.PolicyURI.Entries, 1)
		assert.Equal(t, "https://client.example.org/policy.html", req.PolicyURI.Entries[language.Und])
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
	// Example from https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationRequest
	t.Run("unmarshal Client Registration Request example", func(t *testing.T) {
		marshalled := []byte(`
{
	"application_type": "web",
	"redirect_uris": ["https://client.example.org/callback", "https://client.example.org/callback2"],
	"client_name": "My Example",
	"client_name#ja-Jpan-JP": "クライアント名",
	"logo_uri": "https://client.example.org/logo.png",
	"subject_type": "pairwise",
	"sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
	"token_endpoint_auth_method": "client_secret_basic",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks",
	"userinfo_encrypted_response_alg": "RSA-OAEP-256",
	"userinfo_encrypted_response_enc": "A128CBC-HS256",
	"contacts": ["ve7jtb@example.org", "mary@example.org"],
	"request_uris": ["https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
}
`)
		var req ClientRegistrationRequest
		err := json.Unmarshal(marshalled, &req)
		require.NoError(t, err)
		assert.Equal(t, "web", req.ApplicationType) // cannot use op.ApplicationTypeWeb because of cyclic imports
		assert.Len(t, req.RedirectURIs, 2)
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback")
		assert.Contains(t, req.RedirectURIs, "https://client.example.org/callback2")
		assert.Len(t, req.ClientName.Entries, 2)
		assert.Equal(t, "My Example", req.ClientName.Entries[language.Und])
		assert.Equal(t, "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", req.ClientName.Entries[wantJPTag])
		assert.Len(t, req.LogoURI.Entries, 1)
		assert.Equal(t, "https://client.example.org/logo.png", req.LogoURI.Entries[language.Und])
		assert.Equal(t, "pairwise", req.SubjectType)
		assert.Equal(t, "https://other.example.net/file_of_redirect_uris.json", req.SectorIdentifierURI)
		assert.Equal(t, AuthMethodBasic, req.TokenEndpointAuthMethod)
		assert.Equal(t, "https://client.example.org/my_public_keys.jwks", req.JWKSURI)
		assert.Equal(t, "RSA-OAEP-256", req.UserinfoEncryptedResponseAlg)
		assert.Equal(t, "A128CBC-HS256", req.UserinfoEncryptedResponseEnc)
		assert.Len(t, req.Contacts, 2)
		assert.Contains(t, req.Contacts, "ve7jtb@example.org")
		assert.Contains(t, req.Contacts, "mary@example.org")
		assert.Len(t, req.RequestURIs, 1)
		assert.Contains(t, req.RequestURIs, "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA")
	})
}
func TestClientReadResponse(t *testing.T) {
	wantJPTag, err := language.Parse("ja-Jpan-JP")
	require.NoError(t, err)
	// example from https://openid.net/specs/openid-connect-registration-1_0.html#ReadResponse
	t.Run("marshal example", func(t *testing.T) {
		want := `
{
	"client_id": "s6BhdRkqt3",
	"client_secret": "OylyaC56ijpAQ7G5ZZGL7MMQ6Ap6mEeuhSTFVps2N4Q",
	"client_secret_expires_at": 17514165600,
	"registration_client_uri": "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
	"token_endpoint_auth_method": "client_secret_basic",
	"application_type": "web",
	"redirect_uris": ["https://client.example.org/callback", "https://client.example.org/callback2"],
	"client_name": "My Example",
	"client_name#ja-Jpan-JP": "クライアント名",
	"logo_uri": "https://client.example.org/logo.png",
	"subject_type": "pairwise",
	"sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks",
	"userinfo_encrypted_response_alg": "RSA-OAEP-256",
	"userinfo_encrypted_response_enc": "A128CBC-HS256",
	"contacts": ["ve7jtb@example.org", "mary@example.org"],
	"request_uris": ["https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
}
`
		res := ClientReadResponse{
			ClientRegistrationResponse: ClientRegistrationResponse{
				ClientInformationResponse: ClientInformationResponse{
					ClientMetadata: ClientMetadata{
						RedirectURIs: []string{
							"https://client.example.org/callback",
							"https://client.example.org/callback2",
						},
						TokenEndpointAuthMethod: AuthMethodBasic,
						GrantTypes:              nil,
						ResponseTypes:           nil,
						ClientName: internationalizedfield.InternationalizedField{
							FieldName: "client_name",
							Entries: map[language.Tag]string{
								language.Und: "My Example",
								wantJPTag:    "クライアント名",
							},
						},
						//ClientURI: internationalizedfield.InternationalizedField{},
						LogoURI: internationalizedfield.InternationalizedField{
							FieldName: "logo_uri",
							Entries: map[language.Tag]string{
								language.Und: "https://client.example.org/logo.png",
							},
						},
						//Scope:                        "",
						Contacts: []string{"ve7jtb@example.org", "mary@example.org"},
						//TOSURI:                       nil,
						//PolicyURI:                    nil,
						JWKSURI: "https://client.example.org/my_public_keys.jwks",
						//JWKS:                         jose.JSONWebKeySet{},
						//SoftwareID:                   "",
						//SoftwareVersion:              "",
						ApplicationType:     "web", // cannot use op.ApplicationTypeWeb because of cyclic imports
						SectorIdentifierURI: "https://other.example.net/file_of_redirect_uris.json",
						SubjectType:         "pairwise",
						//IDTokenSignedResponseAlg:     "",
						//IDTokenEncryptedResponseAlg:  "",
						//IDTokenEncryptedResponseEnc:  "",
						//UserinfoSignedResponseAlg:    "",
						UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
						UserinfoEncryptedResponseEnc: "A128CBC-HS256",
						//RequestObjectSigningAlg:      "",
						//RequestObjectEncryptionAlg:   "",
						//RequestObjectEncryptionEnc:   "",
						//TokenEndpointAuthSigningAlg:  "",
						//DefaultMaxAge:                0,
						//RequireAuthTime:              false,
						//DefaultACRValues:             nil,
						//InitiateLoginURI:             "",
						RequestURIs: []string{"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"},
						//PostLogoutRedirectURIs:       nil,
						//ExtraParameters:              nil,
					},
					ClientID:     "s6BhdRkqt3",
					ClientSecret: "OylyaC56ijpAQ7G5ZZGL7MMQ6Ap6mEeuhSTFVps2N4Q",
					//ClientIDIssuedAt:      0,
					ClientSecretExpiresAt: int64(17514165600),
				},
				//RegistrationAccessToken: "",
				RegistrationClientURI: "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
			},
		}

		marshalled, err := json.Marshal(res)
		require.NoError(t, err)

		assert.JSONEq(t, want, string(marshalled))
	})
}

func TestClientInformationErrorResponse(t *testing.T) {
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-23
	t.Run("marshal example", func(t *testing.T) {
		want := `
{
	"error": "invalid_redirect_uri",
	"error_description": "The redirection URI http://sketchy.example.com is not allowed by this server."
}
`
		res := ClientInformationErrorResponse{
			Error:            ClientInformationErrorResponseErrorCodeInvalidRedirectURI,
			ErrorDescription: "The redirection URI http://sketchy.example.com is not allowed by this server.",
		}
		marshalled, err := json.Marshal(res)
		require.NoError(t, err)

		assert.JSONEq(t, want, string(marshalled))
	})
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-23
	t.Run("marshal example", func(t *testing.T) {
		want := `
{
	"error": "invalid_client_metadata",
	"error_description": "The grant type 'authorization_code' must be registered along with the response type 'code' but found only 'implicit' instead."
}
`
		res := ClientInformationErrorResponse{
			Error:            ClientInformationErrorResponseErrorCodeInvalidClientMetadata,
			ErrorDescription: "The grant type 'authorization_code' must be registered along with the response type 'code' but found only 'implicit' instead.",
		}
		marshalled, err := json.Marshal(res)
		require.NoError(t, err)

		assert.JSONEq(t, want, string(marshalled))
	})
	// example from https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError
	t.Run("unmarshal, marshal and unmarshal example", func(t *testing.T) {
		want := `
 {
	"error": "invalid_redirect_uri",
	"error_description": "One or more redirect_uri values are invalid"
}
`
		res := ClientInformationErrorResponse{
			Error:            ClientInformationErrorResponseErrorCodeInvalidRedirectURI,
			ErrorDescription: "One or more redirect_uri values are invalid",
		}
		marshalled, err := json.Marshal(res)
		require.NoError(t, err)

		assert.JSONEq(t, want, string(marshalled))
	})
}

func TestClientRegistrationResponse(t *testing.T) {
	wantJPTag, err := language.Parse("ja-Jpan-JP")
	require.NoError(t, err)
	// from https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
	t.Run("marshal example", func(t *testing.T) {
		want := `
{
	"client_id": "s6BhdRkqt3",
	"client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
	"client_secret_expires_at": 1577858400,
	"registration_access_token": "this.is.an.access.token.value.ffx83",
	"registration_client_uri": "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
	"token_endpoint_auth_method": "client_secret_basic",
	"application_type": "web",
	"redirect_uris": ["https://client.example.org/callback", "https://client.example.org/callback2"],
	"client_name": "My Example",
	"client_name#ja-Jpan-JP": "クライアント名",
	"logo_uri": "https://client.example.org/logo.png",
	"subject_type": "pairwise",
	"sector_identifier_uri": "https://other.example.net/file_of_redirect_uris.json",
	"jwks_uri": "https://client.example.org/my_public_keys.jwks",
	"userinfo_encrypted_response_alg": "RSA-OAEP-256",
	"userinfo_encrypted_response_enc": "A128CBC-HS256",
	"contacts": ["ve7jtb@example.org", "mary@example.org"],
	"request_uris": ["https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA"]
}
`
		res := ClientRegistrationResponse{
			ClientInformationResponse: ClientInformationResponse{
				ClientMetadata: ClientMetadata{
					RedirectURIs: []string{
						"https://client.example.org/callback",
						"https://client.example.org/callback2",
					},
					TokenEndpointAuthMethod: AuthMethodBasic,
					//GrantTypes:              nil,
					//ResponseTypes:           nil,
					ClientName: internationalizedfield.InternationalizedField{
						FieldName: "client_name",
						Entries: map[language.Tag]string{
							language.Und: "My Example",
							wantJPTag:    "クライアント名",
						},
					},
					//ClientURI: nil,
					LogoURI: internationalizedfield.InternationalizedField{
						FieldName: "logo_uri",
						Entries: map[language.Tag]string{
							language.Und: "https://client.example.org/logo.png",
						},
					},
					//Scope: "",
					Contacts: []string{
						"ve7jtb@example.org",
						"mary@example.org",
					},
					//TOSURI:                       nil,
					//PolicyURI:                    nil,
					JWKSURI: "https://client.example.org/my_public_keys.jwks",
					JWKS:    jose.JSONWebKeySet{},
					//SoftwareID:                   "",
					//SoftwareVersion:              "",
					ApplicationType:     "web", // cannot use op.ApplicationTypeWeb because of cyclic imports
					SectorIdentifierURI: "https://other.example.net/file_of_redirect_uris.json",
					SubjectType:         "pairwise",
					//IDTokenSignedResponseAlg:     "",
					//IDTokenEncryptedResponseAlg:  "",
					//IDTokenEncryptedResponseEnc:  "",
					//UserinfoSignedResponseAlg:    "",
					UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
					UserinfoEncryptedResponseEnc: "A128CBC-HS256",
					//RequestObjectSigningAlg:      "",
					//RequestObjectEncryptionAlg:   "",
					//RequestObjectEncryptionEnc:   "",
					//TokenEndpointAuthSigningAlg:  "",
					//DefaultMaxAge:                0,
					//RequireAuthTime:              false,
					//DefaultACRValues:             nil,
					//InitiateLoginURI:             "",
					RequestURIs: []string{
						"https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA",
					},
					//PostLogoutRedirectURIs: nil,
					//ExtraParameters:        nil,
				},
				ClientID:     "s6BhdRkqt3",
				ClientSecret: "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
				//ClientIDIssuedAt:      0,
				ClientSecretExpiresAt: int64(1577858400),
			},
			RegistrationAccessToken: "this.is.an.access.token.value.ffx83",
			RegistrationClientURI:   "https://server.example.com/connect/register?client_id=s6BhdRkqt3",
		}
		marshalled, err := json.Marshal(res)
		require.NoError(t, err)

		assert.JSONEq(t, want, string(marshalled))
	})
	// example from https://www.rfc-editor.org/rfc/rfc7591#page-21
	t.Run("marshal example", func(t *testing.T) {
		want := `
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
`
		res := ClientRegistrationResponse{
			ClientInformationResponse: ClientInformationResponse{
				ClientMetadata: ClientMetadata{
					RedirectURIs: []string{
						"https://client.example.org/callback",
						"https://client.example.org/callback2",
					},
					TokenEndpointAuthMethod: AuthMethodBasic,
					GrantTypes: []GrantType{
						GrantTypeCode,
						GrantTypeRefreshToken,
					},
					//ResponseTypes: nil,
					ClientName: internationalizedfield.InternationalizedField{
						FieldName: "client_name",
						Entries: map[language.Tag]string{
							language.Und: "My Example Client",
							wantJPTag:    "クライアント名",
						},
					},
					//ClientURI: nil,
					LogoURI: internationalizedfield.InternationalizedField{
						FieldName: "logo_uri",
						Entries: map[language.Tag]string{
							language.Und: "https://client.example.org/logo.png",
						},
					},
					//Scope: "",
					//Contacts: nil,
					//TOSURI:    nil,
					//PolicyURI: nil,
					JWKSURI: "https://client.example.org/my_public_keys.jwks",
					//JWKS:                         jose.JSONWebKeySet{},
					//SoftwareID:                   "",
					//SoftwareVersion:              "",
					//ApplicationType: "",
					//SectorIdentifierURI:          "",
					//SubjectType:                  "",
					//IDTokenSignedResponseAlg:     "",
					//IDTokenEncryptedResponseAlg:  "",
					//IDTokenEncryptedResponseEnc:  "",
					//UserinfoSignedResponseAlg:    "",
					//UserinfoEncryptedResponseAlg: "",
					//UserinfoEncryptedResponseEnc: "",
					//RequestObjectSigningAlg:      "",
					//RequestObjectEncryptionAlg:   "",
					//RequestObjectEncryptionEnc:   "",
					//TokenEndpointAuthSigningAlg:  "",
					//DefaultMaxAge:                0,
					//RequireAuthTime:              false,
					//DefaultACRValues:             nil,
					//InitiateLoginURI:             "",
					//RequestURIs:            nil,
					//PostLogoutRedirectURIs: nil,
					ExtraParameters: map[string]interface{}{
						"example_extension_parameter": "example_value",
					},
				},
				ClientID:              "s6BhdRkqt3",
				ClientSecret:          "cf136dc3c1fc93f31185e5885805d",
				ClientIDIssuedAt:      int64(2893256800),
				ClientSecretExpiresAt: int64(2893276800),
			},
			//RegistrationAccessToken: "",
			//RegistrationClientURI:   "",
		}
		marshalled, err := json.Marshal(res)
		require.NoError(t, err)

		assert.JSONEq(t, want, string(marshalled))
	})

	// example from https://www.rfc-editor.org/rfc/rfc7592.html#page-11
	t.Run("marshal example", func(t *testing.T) {
		want := `
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
`
		res := ClientRegistrationResponse{
			ClientInformationResponse: ClientInformationResponse{
				ClientMetadata: ClientMetadata{
					RedirectURIs: []string{
						"https://client.example.org/callback",
						"https://client.example.org/callback2",
					},
					TokenEndpointAuthMethod: AuthMethodBasic,
					GrantTypes: []GrantType{
						GrantTypeCode,
						GrantTypeRefreshToken,
					},
					ResponseTypes: nil,
					ClientName: internationalizedfield.InternationalizedField{
						FieldName: "client_name",
						Entries: map[language.Tag]string{
							language.Und: "My Example Client",
							wantJPTag:    "クライアント名",
						},
					},
					//ClientURI: nil,
					LogoURI: internationalizedfield.InternationalizedField{
						FieldName: "logo_uri",
						Entries: map[language.Tag]string{
							language.Und: "https://client.example.org/logo.png",
						},
					},
					//Scope: "",
					//Contacts: nil,
					//TOSURI:    nil,
					//PolicyURI: nil,
					JWKSURI: "https://client.example.org/my_public_keys.jwks",
					//JWKS:                         jose.JSONWebKeySet{},
					//SoftwareID:                   "",
					//SoftwareVersion:              "",
					//ApplicationType: "",
					//SectorIdentifierURI:          "",
					//SubjectType:                  "",
					//IDTokenSignedResponseAlg:     "",
					//IDTokenEncryptedResponseAlg:  "",
					//IDTokenEncryptedResponseEnc:  "",
					//UserinfoSignedResponseAlg:    "",
					//UserinfoEncryptedResponseAlg: "",
					//UserinfoEncryptedResponseEnc: "",
					//RequestObjectSigningAlg:      "",
					//RequestObjectEncryptionAlg:   "",
					//RequestObjectEncryptionEnc:   "",
					//TokenEndpointAuthSigningAlg:  "",
					//DefaultMaxAge:                0,
					//RequireAuthTime:              false,
					//DefaultACRValues:             nil,
					//InitiateLoginURI:             "",
					//RequestURIs:            nil,
					//PostLogoutRedirectURIs: nil,
					//ExtraParameters: nil,
				},
				ClientID:              "s6BhdRkqt3",
				ClientSecret:          "cf136dc3c1fc93f31185e5885805d",
				ClientIDIssuedAt:      int64(2893256800),
				ClientSecretExpiresAt: int64(2893276800),
			},
			RegistrationAccessToken: "reg-23410913-abewfq.123483",
			RegistrationClientURI:   "https://server.example.com/register/s6BhdRkqt3",
		}
		marshalled, err := json.Marshal(res)
		require.NoError(t, err)

		assert.JSONEq(t, want, string(marshalled))
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
		assert.Len(t, req.ClientName.Entries, 2)
		assert.Equal(t, "My New Example", req.ClientName.Entries[language.Und])
		assert.Equal(t, "Mon Nouvel Exemple", req.ClientName.Entries[language.French])
		assert.Len(t, req.LogoURI.Entries, 2)
		assert.Equal(t, "https://client.example.org/newlogo.png", req.LogoURI.Entries[language.Und])
		assert.Equal(t, "https://client.example.org/fr/newlogo.png", req.LogoURI.Entries[language.French])
	})
}
