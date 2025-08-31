package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserInfo_AppendClaims(t *testing.T) {
	u := new(UserInfo)
	u.AppendClaims("a", "b")
	want := map[string]any{"a": "b"}
	assert.Equal(t, want, u.Claims)

	u.AppendClaims("d", "e")
	want["d"] = "e"
	assert.Equal(t, want, u.Claims)
}

func TestUserInfo_GetAddress(t *testing.T) {
	// nil address
	u := new(UserInfo)
	assert.Equal(t, &UserInfoAddress{}, u.GetAddress())

	u.Address = &UserInfoAddress{PostalCode: "1234"}
	assert.Equal(t, u.Address, u.GetAddress())
}

func TestUserInfoMarshal(t *testing.T) {
	userinfo := &UserInfo{
		Subject: "test",
		Address: &UserInfoAddress{
			StreetAddress: "Test 789\nPostfach 2",
		},
		UserInfoEmail: UserInfoEmail{
			Email:         "test",
			EmailVerified: true,
		},
		UserInfoPhone: UserInfoPhone{
			PhoneNumber:         "0791234567",
			PhoneNumberVerified: true,
		},
		UserInfoProfile: UserInfoProfile{
			Name: "Test",
		},
		Claims: map[string]any{"private_claim": "test"},
	}

	marshal, err := json.Marshal(userinfo)
	assert.NoError(t, err)

	out := new(UserInfo)
	assert.NoError(t, json.Unmarshal(marshal, out))
	expected, err := json.Marshal(out)

	assert.NoError(t, err)
	assert.Equal(t, expected, marshal)

	out2 := new(UserInfo)
	assert.NoError(t, json.Unmarshal(expected, out2))
	assert.Equal(t, out, out2)
}

// TestUserInfoVerifiedFieldsUnmarshal ensures email_verified and phone_number_verified
// handle both standard booleans and AWS Cognito's non-compliant strings.
func TestUserInfoVerifiedFieldsUnmarshal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		json                string
		wantEmailVerified   Bool
		wantPhoneVerified   Bool
	}{
		"booleans true":      {`{"email_verified": true, "phone_number_verified": true}`, true, true},
		"booleans false":     {`{"email_verified": false, "phone_number_verified": false}`, false, false},
		"strings true":       {`{"email_verified": "true", "phone_number_verified": "true"}`, true, true},
		"strings false":      {`{"email_verified": "false", "phone_number_verified": "false"}`, false, false},
		"mixed bool/string":  {`{"email_verified": true, "phone_number_verified": "false"}`, true, false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var got UserInfo
			err := json.Unmarshal([]byte(tt.json), &got)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantEmailVerified, got.EmailVerified)
			assert.Equal(t, tt.wantPhoneVerified, got.PhoneNumberVerified)
		})
	}
}

// TestBoolUnmarshal verifies the Bool type handles various inputs correctly.
func TestBoolUnmarshal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input   string
		want    Bool
		wantErr bool
	}{
		"bool true":      {`true`, true, false},
		"bool false":     {`false`, false, false},
		"string true":    {`"true"`, true, false},
		"string false":   {`"false"`, false, false},
		"string TRUE":    {`"TRUE"`, true, false},
		"string False":   {`"False"`, false, false},
		"invalid string": {`"yes"`, false, true},
		"number":         {`1`, false, true},
		"null":           {`null`, false, false},  // null defaults to false (safe default)
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var got Bool
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
