package oidc

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
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
