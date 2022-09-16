package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserInfoMarshal(t *testing.T) {
	userinfo := NewUserInfo()
	userinfo.SetSubject("test")
	userinfo.SetAddress(NewUserInfoAddress("Test 789\nPostfach 2", "", "", "", "", ""))
	userinfo.SetEmail("test", true)
	userinfo.SetPhone("0791234567", true)
	userinfo.SetName("Test")
	userinfo.AppendClaims("private_claim", "test")

	marshal, err := json.Marshal(userinfo)
	out := NewUserInfo()
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(marshal, out))
	assert.Equal(t, userinfo.GetAddress(), out.GetAddress())
	expected, err := json.Marshal(out)
	assert.NoError(t, err)
	assert.Equal(t, expected, marshal)
}

func TestUserInfoEmailVerifiedUnmarshal(t *testing.T) {
	t.Parallel()

	t.Run("unmarsha email_verified from json bool true", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": true}`)

		var uie userInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, userInfoEmail{
			Email:         "my@email.com",
			EmailVerified: true,
		}, uie)
	})

	t.Run("unmarsha email_verified from json string true", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": "true"}`)

		var uie userInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, userInfoEmail{
			Email:         "my@email.com",
			EmailVerified: true,
		}, uie)
	})

	t.Run("unmarsha email_verified from json bool false", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": false}`)

		var uie userInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, userInfoEmail{
			Email:         "my@email.com",
			EmailVerified: false,
		}, uie)
	})

	t.Run("unmarsha email_verified from json string false", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": "false"}`)

		var uie userInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, userInfoEmail{
			Email:         "my@email.com",
			EmailVerified: false,
		}, uie)
	})
}

// issue 203 test case.
func Test_userinfo_GetAddress_issue_203(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "with address",
			data: `{"address":{"street_address":"Test 789\nPostfach 2"},"email":"test","email_verified":true,"name":"Test","phone_number":"0791234567","phone_number_verified":true,"private_claim":"test","sub":"test"}`,
		},
		{
			name: "without address",
			data: `{"email":"test","email_verified":true,"name":"Test","phone_number":"0791234567","phone_number_verified":true,"private_claim":"test","sub":"test"}`,
		},
		{
			name: "null address",
			data: `{"address":null,"email":"test","email_verified":true,"name":"Test","phone_number":"0791234567","phone_number_verified":true,"private_claim":"test","sub":"test"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &userinfo{}
			if err := json.Unmarshal([]byte(tt.data), info); err != nil {
				t.Fatal(err)
			}

			info.GetAddress().GetCountry() //<- used to panic
		})
	}
}
