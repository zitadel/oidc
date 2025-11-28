package oidc

import (
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

var (
	tokenClaimsData = TokenClaims{
		Issuer:                              "zitadel",
		Subject:                             "hello@me.com",
		Audience:                            Audience{"foo", "bar"},
		Expiration:                          12345,
		IssuedAt:                            12000,
		JWTID:                               "900",
		AuthorizedParty:                     "just@me.com",
		Nonce:                               "6969",
		AuthTime:                            12000,
		NotBefore:                           12000,
		AuthenticationContextClassReference: "something",
		AuthenticationMethodsReferences:     []string{"some", "methods"},
		ClientID:                            "777",
		SignatureAlg:                        jose.ES256,
	}
	accessTokenData = &AccessTokenClaims{
		TokenClaims: tokenClaimsData,
		Scopes:      []string{"email", "phone"},
		Claims: map[string]any{
			"foo": "bar",
		},
	}
	idTokenData = &IDTokenClaims{
		TokenClaims:     tokenClaimsData,
		NotBefore:       12000,
		AccessTokenHash: "acthashhash",
		CodeHash:        "hashhash",
		SessionID:       "666",
		UserInfoProfile: userInfoData.UserInfoProfile,
		UserInfoEmail:   userInfoData.UserInfoEmail,
		UserInfoPhone:   userInfoData.UserInfoPhone,
		Address:         userInfoData.Address,
		Claims: map[string]any{
			"foo": "bar",
		},
	}
	introspectionResponseData = &IntrospectionResponse{
		Active:          true,
		Scope:           SpaceDelimitedArray{"email", "phone"},
		ClientID:        "777",
		TokenType:       "idtoken",
		Expiration:      12345,
		IssuedAt:        12000,
		NotBefore:       12000,
		Subject:         "hello@me.com",
		Audience:        Audience{"foo", "bar"},
		Issuer:          "zitadel",
		JWTID:           "900",
		Username:        "muhlemmer",
		UserInfoProfile: userInfoData.UserInfoProfile,
		UserInfoEmail:   userInfoData.UserInfoEmail,
		UserInfoPhone:   userInfoData.UserInfoPhone,
		Address:         userInfoData.Address,
		Claims: map[string]any{
			"foo": "bar",
		},
	}
	userInfoData = &UserInfo{
		Subject: "hello@me.com",
		UserInfoProfile: UserInfoProfile{
			Name:              "Tim Möhlmann",
			GivenName:         "Tim",
			FamilyName:        "Möhlmann",
			MiddleName:        "Danger",
			Nickname:          "muhlemmer",
			Profile:           "https://github.com/muhlemmer",
			Picture:           "https://avatars.githubusercontent.com/u/5411563?v=4",
			Website:           "https://zitadel.com",
			Gender:            "male",
			Birthdate:         "1st of April",
			Zoneinfo:          "Europe/Amsterdam",
			Locale:            NewLocale(language.Dutch),
			UpdatedAt:         1,
			PreferredUsername: "muhlemmer",
		},
		UserInfoEmail: UserInfoEmail{
			Email:         "tim@zitadel.com",
			EmailVerified: true,
		},
		UserInfoPhone: UserInfoPhone{
			PhoneNumber:         "+1234567890",
			PhoneNumberVerified: true,
		},
		Address: &UserInfoAddress{
			Formatted:     "Sesame street 666\n666-666, Smallvile\nMoon",
			StreetAddress: "Sesame street 666",
			Locality:      "Smallvile",
			Region:        "Outer space",
			PostalCode:    "666-666",
			Country:       "Moon",
		},
		Claims: map[string]any{
			"foo": "bar",
		},
	}
	jwtProfileAssertionData = &JWTProfileAssertionClaims{
		PrivateKeyID: "8888",
		PrivateKey:   []byte("qwerty"),
		Issuer:       "zitadel",
		Subject:      "hello@me.com",
		Audience:     Audience{"foo", "bar"},
		Expiration:   12345,
		IssuedAt:     12000,
		Claims: map[string]any{
			"foo": "bar",
		},
	}
)

func TestTokenClaims(t *testing.T) {
	claims := tokenClaimsData

	assert.Equal(t, claims.Issuer, tokenClaimsData.GetIssuer())
	assert.Equal(t, claims.Subject, tokenClaimsData.GetSubject())
	assert.Equal(t, []string(claims.Audience), tokenClaimsData.GetAudience())
	assert.Equal(t, claims.Expiration.AsTime(), tokenClaimsData.GetExpiration())
	assert.Equal(t, claims.IssuedAt.AsTime(), tokenClaimsData.GetIssuedAt())
	assert.Equal(t, claims.Nonce, tokenClaimsData.GetNonce())
	assert.Equal(t, claims.AuthTime.AsTime(), tokenClaimsData.GetAuthTime())
	assert.Equal(t, claims.AuthorizedParty, tokenClaimsData.GetAuthorizedParty())
	assert.Equal(t, claims.SignatureAlg, tokenClaimsData.GetSignatureAlgorithm())
	assert.Equal(t, claims.AuthenticationContextClassReference, tokenClaimsData.GetAuthenticationContextClassReference())

	claims.SetSignatureAlgorithm(jose.ES384)
	assert.Equal(t, jose.ES384, claims.SignatureAlg)
}

func TestNewAccessTokenClaims(t *testing.T) {
	want := &AccessTokenClaims{
		TokenClaims: TokenClaims{
			Issuer:     "zitadel",
			Subject:    "hello@me.com",
			Audience:   Audience{"foo"},
			Expiration: 12345,
			ClientID:   "foo",
			JWTID:      "900",
		},
	}

	got := NewAccessTokenClaims(
		want.Issuer, want.Subject, nil,
		want.Expiration.AsTime(), want.JWTID, "foo", time.Second,
	)

	// test if the dynamic timestamps are around now,
	// allowing for a delta of 1, just in case we flip on
	// either side of a second boundry.
	nowMinusSkew := NowTime() - 1
	assert.InDelta(t, int64(nowMinusSkew), int64(got.IssuedAt), 1)
	assert.InDelta(t, int64(nowMinusSkew), int64(got.NotBefore), 1)

	// Make equal not fail on dynamic timestamp
	got.IssuedAt = 0
	got.NotBefore = 0

	assert.Equal(t, want, got)
}

func TestIDTokenClaims_GetAccessTokenHash(t *testing.T) {
	assert.Equal(t, idTokenData.AccessTokenHash, idTokenData.GetAccessTokenHash())
}

func TestIDTokenClaims_SetUserInfo(t *testing.T) {
	want := IDTokenClaims{
		TokenClaims: TokenClaims{
			Subject: userInfoData.Subject,
		},
		UserInfoProfile: userInfoData.UserInfoProfile,
		UserInfoEmail:   userInfoData.UserInfoEmail,
		UserInfoPhone:   userInfoData.UserInfoPhone,
		Address:         userInfoData.Address,
		Claims: map[string]any{
			"foo": "bar",
		},
	}

	var got IDTokenClaims
	got.SetUserInfo(userInfoData)

	assert.Equal(t, want, got)
}

func TestNewIDTokenClaims(t *testing.T) {
	want := &IDTokenClaims{
		TokenClaims: TokenClaims{
			Issuer:                              "zitadel",
			Subject:                             "hello@me.com",
			Audience:                            Audience{"foo", "just@me.com"},
			Expiration:                          12345,
			AuthTime:                            12000,
			Nonce:                               "6969",
			AuthenticationContextClassReference: "something",
			AuthenticationMethodsReferences:     []string{"some", "methods"},
			AuthorizedParty:                     "just@me.com",
			ClientID:                            "just@me.com",
		},
	}

	got := NewIDTokenClaims(
		want.Issuer, want.Subject, want.Audience,
		want.Expiration.AsTime(),
		want.AuthTime.AsTime().Add(time.Second),
		want.Nonce, want.AuthenticationContextClassReference,
		want.AuthenticationMethodsReferences, want.AuthorizedParty,
		time.Second,
	)

	// test if the dynamic timestamp is around now,
	// allowing for a delta of 1, just in case we flip on
	// either side of a second boundry.
	nowMinusSkew := NowTime() - 1
	assert.InDelta(t, int64(nowMinusSkew), int64(got.IssuedAt), 1)

	// Make equal not fail on dynamic timestamp
	got.IssuedAt = 0

	assert.Equal(t, want, got)
}

func TestIDTokenClaims_GetUserInfo(t *testing.T) {
	want := &UserInfo{
		Subject:         idTokenData.Subject,
		UserInfoProfile: idTokenData.UserInfoProfile,
		UserInfoEmail:   idTokenData.UserInfoEmail,
		UserInfoPhone:   idTokenData.UserInfoPhone,
		Address:         idTokenData.Address,
		Claims:          idTokenData.Claims,
	}
	got := idTokenData.GetUserInfo()
	assert.Equal(t, want, got)
}

func TestNewLogoutTokenClaims(t *testing.T) {
	want := &LogoutTokenClaims{
		Issuer:     "zitadel",
		Subject:    "hello@me.com",
		Audience:   Audience{"foo", "just@me.com"},
		Expiration: 12345,
		JWTID:      "jwtID",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": struct{}{},
		},
		SessionID: "sessionID",
		Claims:    nil,
	}

	got := NewLogoutTokenClaims(
		want.Issuer,
		want.Subject,
		want.Audience,
		want.Expiration.AsTime(),
		want.JWTID,
		want.SessionID,
		1*time.Second,
	)

	// test if the dynamic timestamp is around now,
	// allowing for a delta of 1, just in case we flip on
	// either side of a second boundry.
	nowMinusSkew := NowTime() - 1
	assert.InDelta(t, int64(nowMinusSkew), int64(got.IssuedAt), 1)

	// Make equal not fail on dynamic timestamp
	got.IssuedAt = 0

	assert.Equal(t, want, got)
}

func TestTokenExchangeResponse_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		marshaled string
		want      TokenExchangeResponse
	}{
		{
			marshaled: `
            {
                "access_token":"access_token",
                "issued_token_type":"test_token",
                "token_type":"test_token",
                "expires_in":12345,
	        	"scope": "lorem ipsum",
	        	"refresh_token": "refresh_token",
	        	"id_token": "id_token"
            }`,
			want: TokenExchangeResponse{
				AccessToken:     "access_token",
				IssuedTokenType: "test_token",
				TokenType:       "test_token",
				ExpiresIn:       12345,
				Scopes:          []string{"lorem", "ipsum"},
				RefreshToken:    "refresh_token",
				IDToken:         "id_token",
			},
		},
		{
			marshaled: `
            {
                "access_token":"access_token",
                "issued_token_type":"test_token",
                "token_type":"test_token",
                "expires_in":"12345",
	        	"scope": "lorem ipsum",
	        	"refresh_token": "refresh_token",
	        	"id_token": "id_token"
            }`,
			want: TokenExchangeResponse{
				AccessToken:     "access_token",
				IssuedTokenType: "test_token",
				TokenType:       "test_token",
				ExpiresIn:       12345,
				Scopes:          []string{"lorem", "ipsum"},
				RefreshToken:    "refresh_token",
				IDToken:         "id_token",
			},
		},
	}
	for _, testCase := range testCases {
		got := &TokenExchangeResponse{}
		err := json.Unmarshal([]byte(testCase.marshaled), got)
		assert.Equal(t, nil, err)
		assert.Equal(t, testCase.want.AccessToken, got.AccessToken)
		assert.Equal(t, testCase.want.IssuedTokenType, got.IssuedTokenType)
		assert.Equal(t, testCase.want.TokenType, got.TokenType)
		assert.Equal(t, testCase.want.ExpiresIn, got.ExpiresIn)
		assert.Equal(t, testCase.want.Scopes, got.Scopes)
		assert.Equal(t, testCase.want.RefreshToken, got.RefreshToken)
		assert.Equal(t, testCase.want.IDToken, got.IDToken)
	}
}
func TestTokenExchangeResponse_MarshalJSON(t *testing.T) {
	testCases := []struct {
		want        string
		unmarshaled TokenExchangeResponse
	}{
		{
			want: `{"access_token":"access_token","issued_token_type":"test_token","token_type":"test_token","expires_in":12345,"scope":"lorem ipsum","refresh_token":"refresh_token","id_token":"id_token"}`,
			unmarshaled: TokenExchangeResponse{
				AccessToken:     "access_token",
				IssuedTokenType: "test_token",
				TokenType:       "test_token",
				ExpiresIn:       12345,
				Scopes:          []string{"lorem", "ipsum"},
				RefreshToken:    "refresh_token",
				IDToken:         "id_token",
			},
		},
	}
	for _, testCase := range testCases {
		got, err := json.Marshal(testCase.unmarshaled)
		assert.Equal(t, nil, err)
		assert.Equal(t, testCase.want, string(got))
	}
}
func TestAccessTokenResponse_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		marshaled string
		want      AccessTokenResponse
	}{
		{
			marshaled: `
            {
                "access_token":"access_token",
                "token_type":"test_token",
	        	"refresh_token": "refresh_token",
                "expires_in":12345,
	        	"id_token": "id_token",
                "state": "state",
	        	"scope": "lorem ipsum"
            }`,
			want: AccessTokenResponse{
				AccessToken:  "access_token",
				TokenType:    "test_token",
				RefreshToken: "refresh_token",
				ExpiresIn:    12345,
				IDToken:      "id_token",
				State:        "state",
				Scope:        []string{"lorem", "ipsum"},
			},
		},
		{
			marshaled: `
            {
                "access_token":"access_token",
                "token_type":"test_token",
	        	"refresh_token": "refresh_token",
                "expires_in":"12345",
	        	"id_token": "id_token",
				"state": "state",
	        	"scope": "lorem ipsum"
            }`,
			want: AccessTokenResponse{
				AccessToken:  "access_token",
				TokenType:    "test_token",
				RefreshToken: "refresh_token",
				ExpiresIn:    12345,
				IDToken:      "id_token",
				State:        "state",
				Scope:        []string{"lorem", "ipsum"},
			},
		},
	}
	for _, testCase := range testCases {
		got := &AccessTokenResponse{}
		err := json.Unmarshal([]byte(testCase.marshaled), got)
		assert.Equal(t, nil, err)
		assert.Equal(t, testCase.want.AccessToken, got.AccessToken)
		assert.Equal(t, testCase.want.TokenType, got.TokenType)
		assert.Equal(t, testCase.want.RefreshToken, got.RefreshToken)
		assert.Equal(t, testCase.want.ExpiresIn, got.ExpiresIn)
		assert.Equal(t, testCase.want.IDToken, got.IDToken)
		assert.Equal(t, testCase.want.State, got.State)
		assert.Equal(t, testCase.want.Scope, got.Scope)
	}
}
func TestAccessTokenResponse_MarshalJSON(t *testing.T) {
	testCases := []struct {
		want        string
		unmarshaled AccessTokenResponse
	}{
		{
			want: `{"access_token":"access_token","token_type":"test_token","refresh_token":"refresh_token","expires_in":12345,"id_token":"id_token","state":"state","scope":"lorem ipsum"}`,
			unmarshaled: AccessTokenResponse{
				AccessToken:  "access_token",
				TokenType:    "test_token",
				RefreshToken: "refresh_token",
				ExpiresIn:    12345,
				IDToken:      "id_token",
				State:        "state",
				Scope:        []string{"lorem", "ipsum"},
			},
		},
	}
	for _, testCase := range testCases {
		got, err := json.Marshal(testCase.unmarshaled)
		assert.Equal(t, nil, err)
		assert.Equal(t, testCase.want, string(got))
	}
}
