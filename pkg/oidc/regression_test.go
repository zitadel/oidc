package oidc

// This file contains common functions and data for regression testing

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"
)

const dataDir = "regression_data"

// jsonFilename builds a filename for the regression testdata.
// dataDir/<type_name>.json
func jsonFilename(obj interface{}) string {
	name := fmt.Sprintf("%T.json", obj)
	return path.Join(
		dataDir,
		strings.TrimPrefix(name, "*"),
	)
}

func encodeJSON(t *testing.T, w io.Writer, obj interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	require.NoError(t, enc.Encode(obj))
}

var (
	accessTokenRegressData = &AccessTokenClaims{
		RegisteredAccessTokenClaims: RegisteredAccessTokenClaims{
			TokenClaims: TokenClaims{
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
			},
			NotBefore:            12000,
			CodeHash:             "hashhash",
			SessionID:            "666",
			Scopes:               []string{"email", "phone"},
			AccessTokenUseNumber: 22,
		},
		Claims: map[string]interface{}{
			"foo": "bar",
		},
	}
	idTokenRegressData = &IDTokenClaims{
		RegisteredIDTokenClaims: RegisteredIDTokenClaims{
			TokenClaims: TokenClaims{
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
			},
			NotBefore:       12000,
			AccessTokenHash: "acthashhash",
			CodeHash:        "hashhash",
			UserInfoProfile: userInfoRegressData.UserInfoProfile,
			UserInfoEmail:   userInfoRegressData.UserInfoEmail,
			UserInfoPhone:   userInfoRegressData.UserInfoPhone,
			Address:         userInfoRegressData.Address,
		},
		Claims: map[string]interface{}{
			"foo": "bar",
		},
	}
	introspectionResponseRegressData = &IntrospectionResponse{
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
		UserInfoProfile: userInfoRegressData.UserInfoProfile,
		UserInfoEmail:   userInfoRegressData.UserInfoEmail,
		UserInfoPhone:   userInfoRegressData.UserInfoPhone,
		Address:         userInfoRegressData.Address,
		Claims: map[string]interface{}{
			"foo": "bar",
		},
	}
	userInfoRegressData = &UserInfo{
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
	jwtProfileAssertionRegressData = &jwtProfileAssertion{
		PrivateKeyID: "8888",
		PrivateKey:   []byte("qwerty"),
		Issuer:       "zitadel",
		Subject:      "hello@me.com",
		Audience:     Audience{"foo", "bar"},
		Expiration:   12345,
		IssuedAt:     12000,
		customClaims: map[string]interface{}{
			"foo": "bar",
		},
	}
	regressionData = []interface{}{
		accessTokenRegressData,
		idTokenRegressData,
		introspectionResponseRegressData,
		userInfoRegressData,
		jwtProfileAssertionRegressData,
	}
)
