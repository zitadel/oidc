package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserInfoMarshal(t *testing.T) {
	userinfo := &UserInfo{
		Subject: "test",
		Address: UserInfoAddress{
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
	assert.Equal(t, userinfo, out)
	expected, err := json.Marshal(out)

	assert.NoError(t, err)
	assert.Equal(t, expected, marshal)
}

func TestUserInfoEmailVerifiedUnmarshal(t *testing.T) {
	t.Parallel()

	t.Run("unmarshal email_verified from json bool true", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": true}`)

		var uie UserInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, UserInfoEmail{
			Email:         "my@email.com",
			EmailVerified: true,
		}, uie)
	})

	t.Run("unmarsha email_verified from json string true", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": "true"}`)

		var uie UserInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, UserInfoEmail{
			Email:         "my@email.com",
			EmailVerified: true,
		}, uie)
	})

	t.Run("unmarsha email_verified from json bool false", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": false}`)

		var uie UserInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, UserInfoEmail{
			Email:         "my@email.com",
			EmailVerified: false,
		}, uie)
	})

	t.Run("unmarsha email_verified from json string false", func(t *testing.T) {
		jsonBool := []byte(`{"email": "my@email.com", "email_verified": "false"}`)

		var uie UserInfoEmail

		err := json.Unmarshal(jsonBool, &uie)
		assert.NoError(t, err)
		assert.Equal(t, UserInfoEmail{
			Email:         "my@email.com",
			EmailVerified: false,
		}, uie)
	})
}
