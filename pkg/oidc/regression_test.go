package oidc

// This file contains common functions and data for regression testing

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"
)

const dataDir = "regression_data"

// jsonFilename builds a filename for the regression testdata.
// dataDir/<type_name>.json
func jsonFilename(obj interface{}) string {
	name := fmt.Sprintf("%T.json", obj)
	name, _ = strings.CutPrefix(name, "*")
	return path.Join(dataDir, name)
}

func encodeJSON(t *testing.T, w io.Writer, obj interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	require.NoError(t, enc.Encode(obj))
}

var (
	accessTokenRegressData = &accessTokenClaims{
		Issuer:                              "zitadel",
		Subject:                             "hello@me.com",
		Audience:                            Audience{"foo", "bar"},
		Expiration:                          Time(time.Unix(12345, 0)),
		IssuedAt:                            Time(time.Unix(12000, 0)),
		NotBefore:                           Time(time.Unix(12000, 0)),
		JWTID:                               "900",
		AuthorizedParty:                     "just@me.com",
		Nonce:                               "6969",
		AuthTime:                            Time(time.Unix(12000, 0)),
		CodeHash:                            "hashhash",
		AuthenticationContextClassReference: "something",
		AuthenticationMethodsReferences:     []string{"some", "methods"},
		SessionID:                           "666",
		Scopes:                              []string{"email", "phone"},
		ClientID:                            "777",
		AccessTokenUseNumber:                22,
		claims: map[string]interface{}{
			"foo": "bar",
		},
		signatureAlg: jose.ES256,
	}
	idTokenRegressData = &idTokenClaims{
		Issuer:                              "zitadel",
		Audience:                            Audience{"foo", "bar"},
		Expiration:                          Time(time.Unix(12345, 0)),
		NotBefore:                           Time(time.Unix(12000, 0)),
		IssuedAt:                            Time(time.Unix(12000, 0)),
		JWTID:                               "900",
		AuthorizedParty:                     "just@me.com",
		Nonce:                               "6969",
		AuthTime:                            Time(time.Unix(12000, 0)),
		AccessTokenHash:                     "acthashhash",
		CodeHash:                            "hashhash",
		AuthenticationContextClassReference: "something",
		AuthenticationMethodsReferences:     []string{"some", "methods"},
		ClientID:                            "777",
		UserInfo:                            userInfoRegressData,
		signatureAlg:                        jose.ES256,
	}
	introspectionResponseRegressData = &introspectionResponse{
		Active:          true,
		Scope:           SpaceDelimitedArray{"email", "phone"},
		ClientID:        "777",
		TokenType:       "idtoken",
		Expiration:      Time(time.Unix(12345, 0)),
		IssuedAt:        Time(time.Unix(12000, 0)),
		NotBefore:       Time(time.Unix(12000, 0)),
		Subject:         "hello@me.com",
		Audience:        Audience{"foo", "bar"},
		Issuer:          "zitadel",
		JWTID:           "900",
		userInfoProfile: userInfoRegressData.userInfoProfile,
		userInfoEmail:   userInfoRegressData.userInfoEmail,
		userInfoPhone:   userInfoRegressData.userInfoPhone,
		Address:         userInfoRegressData.Address,
		claims: map[string]interface{}{
			"foo": "bar",
		},
	}
	userInfoRegressData = &userinfo{
		Subject: "hello@me.com",
		userInfoProfile: userInfoProfile{
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
			Locale:            language.Dutch,
			UpdatedAt:         Time(time.Unix(1, 1)),
			PreferredUsername: "muhlemmer",
		},
		userInfoEmail: userInfoEmail{
			Email:         "tim@zitadel.com",
			EmailVerified: true,
		},
		userInfoPhone: userInfoPhone{
			PhoneNumber:         "+1234567890",
			PhoneNumberVerified: true,
		},
		Address: &userInfoAddress{
			Formatted:     "Sesame street 666\n666-666, Smallvile\nMoon",
			StreetAddress: "Sesame street 666",
			Locality:      "Smallvile",
			Region:        "Outer space",
			PostalCode:    "666-666",
			Country:       "Moon",
		},
		claims: map[string]interface{}{
			"foo": "bar",
		},
	}
	jwtProfileAssertionRegressData = &jwtProfileAssertion{
		PrivateKeyID: "8888",
		PrivateKey:   []byte("qwerty"),
		Issuer:       "zitadel",
		Subject:      "hello@me.com",
		Audience:     Audience{"foo", "bar"},
		Expiration:   Time(time.Unix(12345, 0)),
		IssuedAt:     Time(time.Unix(12000, 0)),
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
