package oidc_test

import (
	"encoding/json"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestJWKThumbprint(t *testing.T) {
	const raw = `{"kty":"EC","crv":"P-256","x":"ukpv3fU6tqQKaUwcdBAQoK3IHvJIW__9yNd1oR7qvZc","y":"nBBxXrx0Nziwg_evfUMUUgnGKKUf2ATpWG9EojnUoU4"}`
	var jwk jose.JSONWebKey
	require.NoError(t, json.Unmarshal([]byte(raw), &jwk))

	got, err := oidc.JWKThumbprint(&jwk)
	require.NoError(t, err)
	assert.Equal(t, "dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw", got)
}

func TestValidDPoPJKT(t *testing.T) {
	assert.True(t, oidc.ValidDPoPJKT("dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"))
	assert.False(t, oidc.ValidDPoPJKT(""))
	assert.False(t, oidc.ValidDPoPJKT("too-short"))
	assert.False(t, oidc.ValidDPoPJKT("dnfb1T9jil/gOhti60baHs_WD_a4D8JN9VDJXbmBmGw"))
	assert.False(t, oidc.ValidDPoPJKT("dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGw="))
	assert.False(t, oidc.ValidDPoPJKT("dnfb1T9jil_gOhti60baHs_WD_a4D8JN9VDJXbmBmGx"))
}

func TestCanonicalJWK(t *testing.T) {
	const raw = `{"kty":"EC","crv":"P-256","x":"ukpv3fU6tqQKaUwcdBAQoK3IHvJIW__9yNd1oR7qvZc","y":"nBBxXrx0Nziwg_evfUMUUgnGKKUf2ATpWG9EojnUoU4","kid":"client-key","use":"sig","alg":"ES256"}`
	var jwk jose.JSONWebKey
	require.NoError(t, json.Unmarshal([]byte(raw), &jwk))

	got, err := oidc.CanonicalJWK(&jwk)
	require.NoError(t, err)
	assert.JSONEq(t, `{"kty":"EC","crv":"P-256","x":"ukpv3fU6tqQKaUwcdBAQoK3IHvJIW__9yNd1oR7qvZc","y":"nBBxXrx0Nziwg_evfUMUUgnGKKUf2ATpWG9EojnUoU4"}`, string(got))
}

func TestCodeHash(t *testing.T) {
	assert.Equal(t, "o1uBp9eSe3DsmScN0jYriFgKKFdK-BLywC9WRpV5GG8", oidc.CodeHash("SplxlOBeZQQYbYS6WxSbIA"))
}

func TestDPoPProofClaimsRejectsStringIssuedAt(t *testing.T) {
	var claims oidc.DPoPProofClaims
	assert.Error(t, json.Unmarshal([]byte(`{"iat":"2026-07-29T12:00:00Z"}`), &claims))
}

// TestIDTokenClaimsConfirmationRoundTrip pins the invariant that a `cnf` claim
// parses into IDTokenClaims.Confirmation. Several fail-closed checks depend on
// it (notably the OP refusing a key-bound ID Token as a Token Exchange
// subject_token); if `cnf` stopped unmarshalling here, those would silently
// become dead code and the checks would pass everything.
func TestIDTokenClaimsConfirmationRoundTrip(t *testing.T) {
	const raw = `{"iss":"https://op.example.com","sub":"subject","cnf":{"jwk":{"kty":"EC","crv":"P-256","x":"a","y":"b"}}}`

	var claims oidc.IDTokenClaims
	require.NoError(t, json.Unmarshal([]byte(raw), &claims))
	require.NotNil(t, claims.Confirmation)
	assert.JSONEq(t, `{"kty":"EC","crv":"P-256","x":"a","y":"b"}`, string(claims.Confirmation.JWK))

	// And it survives a marshal/unmarshal cycle without duplicating.
	marshalled, err := json.Marshal(&claims)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(marshalled), `"cnf"`))

	var again oidc.IDTokenClaims
	require.NoError(t, json.Unmarshal(marshalled, &again))
	require.NotNil(t, again.Confirmation)
	assert.JSONEq(t, string(claims.Confirmation.JWK), string(again.Confirmation.JWK))

	// An unbound token must have no cnf at all.
	unbound, err := json.Marshal(&oidc.IDTokenClaims{})
	require.NoError(t, err)
	assert.NotContains(t, string(unbound), "cnf")
}
