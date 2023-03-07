package oidc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionResponse_SetUserInfo(t *testing.T) {
	tests := []struct {
		name  string
		start *IntrospectionResponse
		want  *IntrospectionResponse
	}{
		{

			name:  "nil claims",
			start: &IntrospectionResponse{},
			want: &IntrospectionResponse{
				Subject:         userInfoData.Subject,
				Username:        userInfoData.PreferredUsername,
				Address:         userInfoData.Address,
				UserInfoProfile: userInfoData.UserInfoProfile,
				UserInfoEmail:   userInfoData.UserInfoEmail,
				UserInfoPhone:   userInfoData.UserInfoPhone,
				Claims:          userInfoData.Claims,
			},
		},
		{

			name: "merge claims",
			start: &IntrospectionResponse{
				Claims: map[string]any{
					"hello": "world",
				},
			},
			want: &IntrospectionResponse{
				Subject:         userInfoData.Subject,
				Username:        userInfoData.PreferredUsername,
				Address:         userInfoData.Address,
				UserInfoProfile: userInfoData.UserInfoProfile,
				UserInfoEmail:   userInfoData.UserInfoEmail,
				UserInfoPhone:   userInfoData.UserInfoPhone,
				Claims: map[string]any{
					"foo":   "bar",
					"hello": "world",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.start.SetUserInfo(userInfoData)
			assert.Equal(t, tt.want, tt.start)
		})
	}
}

func TestIntrospectionResponse_GetAddress(t *testing.T) {
	// nil address
	i := new(IntrospectionResponse)
	assert.Equal(t, &UserInfoAddress{}, i.GetAddress())

	i.Address = &UserInfoAddress{PostalCode: "1234"}
	assert.Equal(t, i.Address, i.GetAddress())
}

func TestIntrospectionResponse_MarshalJSON(t *testing.T) {
	got, err := json.Marshal(&IntrospectionResponse{
		UserInfoProfile: UserInfoProfile{
			PreferredUsername: "muhlemmer",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(got), `{"active":false,"username":"muhlemmer","preferred_username":"muhlemmer"}`)
}
