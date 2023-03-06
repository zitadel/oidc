package rp_test

import (
	"context"
	"fmt"

	tu "github.com/zitadel/oidc/v2/internal/testutil"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

// MyCustomClaims extends the TokenClaims base,
// so it implments the oidc.Claims interface.
// Instead of carying a map, we add needed fields
// to the struct for type safe access.
type MyCustomClaims struct {
	oidc.TokenClaims
	NotBefore       oidc.Time `json:"nbf,omitempty"`
	AccessTokenHash string    `json:"at_hash,omitempty"`
	Foo             string    `json:"foo,omitempty"`
	Bar             *Nested   `json:"bar,omitempty"`
}

// GetAccessTokenHash is required to implement
// the oidc.IDClaims interface.
func (c *MyCustomClaims) GetAccessTokenHash() string {
	return c.AccessTokenHash
}

// Nested struct types are also possible.
type Nested struct {
	Count int      `json:"count,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

/*
idToken caries the following claims. foo and bar are custom claims

	{
		"acr": "something",
		"amr": [
			"foo",
			"bar"
		],
		"at_hash": "GKlH62ujLglHjxdM6ezzyQ",
		"aud": [
			"unit",
			"test",
			"555666"
		],
		"auth_time": 1678096954,
		"azp": "555666",
		"bar": {
			"count": 22,
			"tags": [
				"some",
				"tags"
			]
		},
		"client_id": "555666",
		"exp": 4802234675,
		"foo": "Hello, World!",
		"iat": 1678097014,
		"iss": "local.com",
		"jti": "9876",
		"nbf": 1678097014,
		"nonce": "12345",
		"sub": "tim@local.com"
	}
*/
const idToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOlsidW5pdCIsInRlc3QiXSwiYmFyIjoid29ybGQiLCJleHAiOjQ4MDIwMjU5MjAsImZvbyI6ImhlbGxvIiwiaWF0IjoxNjc3ODg4MjU5LCJpc3MiOiJsb2NhbC5jb20iLCJqdGkiOiI5ODc2IiwibmJmIjoxNjc3ODg4MjU5LCJzdWIiOiJ0aW1AbG9jYWwuY29tIn0.TbKRJnfyfn1PTC46VVXqqiKZl4gVmRPdQy8dxXvMtp1SAeMU4gSuu2qb-bNlVgFqQ5YqvveKH4mswcUf7DrqPx79roBEY1VZ6R0e10beZBg0UZ0XaBf9V9YJGTRQNEuETRjl6kMwVav4oyP8ZW74-AOrgSql7vxCX3FDRTRxt_7oeFRz2YzugFdHPOqQo4IHudQNMN9WD9b3QgoKDyj0BGxAQ9WpDE5N7WKIf6fXipSXJBQmf22QazXFZcUOGfKdhFYZ9eSlZQRDFJTguEtKwzk7wcxt6aJBsU-AEha2SucRXe3j7J56hAEsN5gC5i9edSdr8ebzrhnnLJ1t-PafhQ`
const accessToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOlsidW5pdCIsInRlc3QiXSwiYmFyIjp7ImNvdW50IjoyMiwidGFncyI6WyJzb21lIiwidGFncyJdfSwiZXhwIjo0ODAyMjM0Njc1LCJmb28iOiJIZWxsbywgV29ybGQhIiwiaWF0IjoxNjc4MDk3MDE0LCJpc3MiOiJsb2NhbC5jb20iLCJqdGkiOiI5ODc2IiwibmJmIjoxNjc4MDk3MDE0LCJzdWIiOiJ0aW1AbG9jYWwuY29tIn0.OUgk-B7OXjYlYFj-nogqSDJiQE19tPrbzqUHEAjcEiJkaWo6-IpGVfDiGKm-TxjXQsNScxpaY0Pg3XIh1xK6TgtfYtoLQm-5RYw_mXgb9xqZB2VgPs6nNEYFUDM513MOU0EBc0QMyqAEGzW-HiSPAb4ugCvkLtM1yo11Xyy6vksAdZNs_mJDT4X3vFXnr0jk0ugnAW6fTN3_voC0F_9HQUAkmd750OIxkAHxAMvEPQcpbLHenVvX_Q0QMrzClVrxehn5TVMfmkYYg7ocr876Bq9xQGPNHAcrwvVIJqdg5uMUA38L3HC2BEueG6furZGvc7-qDWAT1VR9liM5ieKpPg`

func ExampleVerifyTokens_customClaims() {
	v := rp.NewIDTokenVerifier("local.com", "555666", tu.KeySet{})

	// VerifyAccessToken can be called with the *MyCustomClaims.
	claims, err := rp.VerifyTokens[*MyCustomClaims](context.TODO(), accessToken, idToken, v)
	if err != nil {
		panic(err)
	}
	// Here we have typesafe access to the custom claims
	fmt.Println(claims.Foo, claims.Bar.Count, claims.Bar.Tags)
	// Output: Hello, World! 22 [some tags]
}
