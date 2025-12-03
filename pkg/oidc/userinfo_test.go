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

	tests := []struct {
		name              string
		json              string
		wantEmailVerified Bool
		wantPhoneVerified Bool
	}{
		{
			name:              "booleans true",
			json:              `{"email_verified": true, "phone_number_verified": true}`,
			wantEmailVerified: true,
			wantPhoneVerified: true,
		},
		{
			name:              "booleans false",
			json:              `{"email_verified": false, "phone_number_verified": false}`,
			wantEmailVerified: false,
			wantPhoneVerified: false,
		},
		{
			name:              "strings true",
			json:              `{"email_verified": "true", "phone_number_verified": "true"}`,
			wantEmailVerified: true,
			wantPhoneVerified: true,
		},
		{
			name:              "strings false",
			json:              `{"email_verified": "false", "phone_number_verified": "false"}`,
			wantEmailVerified: false,
			wantPhoneVerified: false,
		},
		{
			name:              "mixed bool/string",
			json:              `{"email_verified": true, "phone_number_verified": "false"}`,
			wantEmailVerified: true,
			wantPhoneVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

	tests := []struct {
		name    string
		input   string
		want    Bool
		wantErr bool
	}{
		{
			name:  "bool true",
			input: `true`,
			want:  true,
		},
		{
			name:  "bool false",
			input: `false`,
			want:  false,
		},
		{
			name:  "string true",
			input: `"true"`,
			want:  true,
		},
		{
			name:  "string false",
			input: `"false"`,
			want:  false,
		},
		{
			name:    "invalid string",
			input:   `"yes"`,
			wantErr: true,
		},
		{
			name:    "number",
			input:   `1`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Bool
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
