package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"
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
		AuthenticationContextClassReference: "something",
		AuthenticationMethodsReferences:     []string{"some", "methods"},
		ClientID:                            "777",
		SignatureAlg:                        jose.ES256,
	}
	accessTokenData = &AccessTokenClaims{
		TokenClaims:          tokenClaimsData,
		NotBefore:            12000,
		CodeHash:             "hashhash",
		SessionID:            "666",
		Scopes:               []string{"email", "phone"},
		AccessTokenUseNumber: 22,
		Claims: map[string]interface{}{
			"foo": "bar",
		},
	}
	idTokenData = &IDTokenClaims{
		TokenClaims:     tokenClaimsData,
		NotBefore:       12000,
		AccessTokenHash: "acthashhash",
		CodeHash:        "hashhash",
		UserInfoProfile: userInfoData.UserInfoProfile,
		UserInfoEmail:   userInfoData.UserInfoEmail,
		UserInfoPhone:   userInfoData.UserInfoPhone,
		Address:         userInfoData.Address,
		Claims: map[string]interface{}{
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
		Claims: map[string]interface{}{
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
		Address: UserInfoAddress{
			Formatted:     "Sesame street 666\n666-666, Smallvile\nMoon",
			StreetAddress: "Sesame street 666",
			Locality:      "Smallvile",
			Region:        "Outer space",
			PostalCode:    "666-666",
			Country:       "Moon",
		},
		Claims: map[string]interface{}{
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
		Claims: map[string]interface{}{
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
			JWTID:      "900",
		},
	}

	got := NewAccessTokenClaims(
		want.Issuer, want.Subject, nil,
		want.Expiration.AsTime(), want.JWTID, "foo", time.Second,
	)

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

	// Make equal not fail on dynamic timestamp
	got.IssuedAt = 0

	assert.Equal(t, want, got)
}
