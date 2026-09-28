package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTTokenRequest_MarshalJSON_JWTID(t *testing.T) {
	var req JWTTokenRequest
	require.NoError(t, json.Unmarshal([]byte(`{"iss":"client","sub":"client","aud":"issuer","iat":1,"exp":2,"jti":"old","custom":"kept"}`), &req))

	// jti is omitted when empty; the parsed value must not come back.
	req.JWTID = ""
	got := marshalToMap(t, &req)
	assert.NotContains(t, got, "jti")
	assert.Equal(t, "kept", got["custom"])

	req.JWTID = "new"
	got = marshalToMap(t, &req)
	assert.Equal(t, "new", got["jti"])
	assert.Equal(t, "kept", got["custom"])
}

func marshalToMap(t *testing.T, req *JWTTokenRequest) map[string]any {
	t.Helper()
	b, err := json.Marshal(req)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(b, &got))
	return got
}
