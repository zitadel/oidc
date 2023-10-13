package op_test

import (
	"context"
	"fmt"

	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// MyCustomClaims extends the TokenClaims base,
// so it implements the oidc.Claims interface.
// Instead of carrying a map, we add needed fields// to the struct for type safe access.
type MyCustomClaims struct {
	oidc.TokenClaims
	NotBefore            oidc.Time `json:"nbf,omitempty"`
	CodeHash             string    `json:"c_hash,omitempty"`
	SessionID            string    `json:"sid,omitempty"`
	Scopes               []string  `json:"scope,omitempty"`
	AccessTokenUseNumber int       `json:"at_use_nbr,omitempty"`
	Foo                  string    `json:"foo,omitempty"`
	Bar                  *Nested   `json:"bar,omitempty"`
}

// Nested struct types are also possible.
type Nested struct {
	Count int      `json:"count,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

/*
accessToken carries the following claims. foo and bar are custom claims

	{
		"aud": [
			"unit",
			"test"
		],
		"bar": {
			"count": 22,
			"tags": [
				"some",
				"tags"
			]
		},
		"exp": 4802234675,
		"foo": "Hello, World!",
		"iat": 1678097014,
		"iss": "local.com",
		"jti": "9876",
		"nbf": 1678097014,
		"sub": "tim@local.com"
	}
*/
const accessToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOlsidW5pdCIsInRlc3QiXSwiYmFyIjp7ImNvdW50IjoyMiwidGFncyI6WyJzb21lIiwidGFncyJdfSwiZXhwIjo0ODAyMjM0Njc1LCJmb28iOiJIZWxsbywgV29ybGQhIiwiaWF0IjoxNjc4MDk3MDE0LCJpc3MiOiJsb2NhbC5jb20iLCJqdGkiOiI5ODc2IiwibmJmIjoxNjc4MDk3MDE0LCJzdWIiOiJ0aW1AbG9jYWwuY29tIn0.OUgk-B7OXjYlYFj-nogqSDJiQE19tPrbzqUHEAjcEiJkaWo6-IpGVfDiGKm-TxjXQsNScxpaY0Pg3XIh1xK6TgtfYtoLQm-5RYw_mXgb9xqZB2VgPs6nNEYFUDM513MOU0EBc0QMyqAEGzW-HiSPAb4ugCvkLtM1yo11Xyy6vksAdZNs_mJDT4X3vFXnr0jk0ugnAW6fTN3_voC0F_9HQUAkmd750OIxkAHxAMvEPQcpbLHenVvX_Q0QMrzClVrxehn5TVMfmkYYg7ocr876Bq9xQGPNHAcrwvVIJqdg5uMUA38L3HC2BEueG6furZGvc7-qDWAT1VR9liM5ieKpPg`

func ExampleVerifyAccessToken_customClaims() {
	v := op.NewAccessTokenVerifier("local.com", tu.KeySet{})

	// VerifyAccessToken can be called with the *MyCustomClaims.
	claims, err := op.VerifyAccessToken[*MyCustomClaims](context.TODO(), accessToken, v)
	if err != nil {
		panic(err)
	}

	// Here we have typesafe access to the custom claims
	fmt.Println(claims.Foo, claims.Bar.Count, claims.Bar.Tags)
	// Output: Hello, World! 22 [some tags]
}
