package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceAuthorizationResponse_UnmarshalJSON(t *testing.T) {
	jsonStr := `{
		"device_code": "deviceCode",
		"user_code": "userCode",
		"verification_url": "http://example.com/verify",
		"expires_in": 3600,
		"interval": 5
	}`

	expected := &DeviceAuthorizationResponse{
		DeviceCode:      "deviceCode",
		UserCode:        "userCode",
		VerificationURI: "http://example.com/verify",
		ExpiresIn:       3600,
		Interval:        5,
	}

	var resp DeviceAuthorizationResponse
	err := resp.UnmarshalJSON([]byte(jsonStr))
	assert.NoError(t, err)
	assert.Equal(t, expected, &resp)
}
