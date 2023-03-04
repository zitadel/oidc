package op_test

import (
	"context"
	"fmt"

	tu "github.com/zitadel/oidc/v2/internal/testutil"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
)

// MyCustomClaims extends the TokenClaims base,
// so it implments the oidc.Claims interface.
// Instead of carying a map, we add needed fields
// to the struct for type safe access.
type MyCustomClaims struct {
	oidc.TokenClaims
	NotBefore            oidc.Time `json:"nbf,omitempty"`
	CodeHash             string    `json:"c_hash,omitempty"`
	SessionID            string    `json:"sid,omitempty"`
	Scopes               []string  `json:"scope,omitempty"`
	AccessTokenUseNumber int       `json:"at_use_nbr,omitempty"`
	Foo                  string    `json:"foo,omitempty"`
	Bar                  string    `json:"bar,omitempty"`
}

/*
accessToken caries the following claims. foo and bar are custom claims

	{
		"aud": [
			"unit",
			"test"
		],
		"bar": "world",
		"exp": 4802025920,
		"foo": "hello",
		"iat": 1677888259,
		"iss": "local.com",
		"jti": "9876",
		"nbf": 1677888259,
		"sub": "tim@local.com"
	}
*/
const accessToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOlsidW5pdCIsInRlc3QiXSwiYmFyIjoid29ybGQiLCJleHAiOjQ4MDIwMjU5MjAsImZvbyI6ImhlbGxvIiwiaWF0IjoxNjc3ODg4MjU5LCJpc3MiOiJsb2NhbC5jb20iLCJqdGkiOiI5ODc2IiwibmJmIjoxNjc3ODg4MjU5LCJzdWIiOiJ0aW1AbG9jYWwuY29tIn0.TbKRJnfyfn1PTC46VVXqqiKZl4gVmRPdQy8dxXvMtp1SAeMU4gSuu2qb-bNlVgFqQ5YqvveKH4mswcUf7DrqPx79roBEY1VZ6R0e10beZBg0UZ0XaBf9V9YJGTRQNEuETRjl6kMwVav4oyP8ZW74-AOrgSql7vxCX3FDRTRxt_7oeFRz2YzugFdHPOqQo4IHudQNMN9WD9b3QgoKDyj0BGxAQ9WpDE5N7WKIf6fXipSXJBQmf22QazXFZcUOGfKdhFYZ9eSlZQRDFJTguEtKwzk7wcxt6aJBsU-AEha2SucRXe3j7J56hAEsN5gC5i9edSdr8ebzrhnnLJ1t-PafhQ`

func ExampleVerifyAccessToken_customClaims() {
	v := op.NewAccessTokenVerifier("local.com", tu.KeySet{})

	// Now VerifyAccessToken can be called with the *MyCustomClaims type to provide
	// type safe access to all the Claims.
	claims, err := op.VerifyAccessToken[*MyCustomClaims](context.TODO(), accessToken, v)
	if err != nil {
		panic(err)
	}
	fmt.Println(claims.Foo, claims.Bar)
	// Output: hello world
}
