package rp_test

import (
	"context"
	"fmt"

	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// MyCustomClaims extends the TokenClaims base,
// so it implmeents the oidc.Claims interface.
// Instead of carrying a map, we add needed fields// to the struct for type safe access.
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
idToken carries the following claims. foo and bar are custom claims

	{
		"acr": "something",
		"amr": [
			"foo",
			"bar"
		],
		"at_hash": "2dzbm_vIxy-7eRtqUIGPPw",
		"aud": [
			"unit",
			"test",
			"555666"
		],
		"auth_time": 1678100961,
		"azp": "555666",
		"bar": {
			"count": 22,
			"tags": [
				"some",
				"tags"
			]
		},
		"client_id": "555666",
		"exp": 4802238682,
		"foo": "Hello, World!",
		"iat": 1678101021,
		"iss": "local.com",
		"jti": "9876",
		"nbf": 1678101021,
		"nonce": "12345",
		"sub": "tim@local.com"
	}
*/
const idToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhY3IiOiJzb21ldGhpbmciLCJhbXIiOlsiZm9vIiwiYmFyIl0sImF0X2hhc2giOiIyZHpibV92SXh5LTdlUnRxVUlHUFB3IiwiYXVkIjpbInVuaXQiLCJ0ZXN0IiwiNTU1NjY2Il0sImF1dGhfdGltZSI6MTY3ODEwMDk2MSwiYXpwIjoiNTU1NjY2IiwiYmFyIjp7ImNvdW50IjoyMiwidGFncyI6WyJzb21lIiwidGFncyJdfSwiY2xpZW50X2lkIjoiNTU1NjY2IiwiZXhwIjo0ODAyMjM4NjgyLCJmb28iOiJIZWxsbywgV29ybGQhIiwiaWF0IjoxNjc4MTAxMDIxLCJpc3MiOiJsb2NhbC5jb20iLCJqdGkiOiI5ODc2IiwibmJmIjoxNjc4MTAxMDIxLCJub25jZSI6IjEyMzQ1Iiwic3ViIjoidGltQGxvY2FsLmNvbSJ9.t3GXSfVNNwiW1Suv9_84v0sdn2_-RWHVxhphhRozDXnsO7SDNOlGnEioemXABESxSzMclM7gB7mYy5Qah2ZUNx7eP5t2njoxEYfavgHwx7UJZ2NCg8NDPQyr-hlxelEcfdXK-I0oTd-FRDvF4rqPkD9Us52IpnplChCxnHFgh4wKwPqZZjv2IXVCtn0ilKW3hff1rMOYKEuLRcN2YP0gkyuqyHvcf2dMmjod0t4sLOTJ82rsCbMBC5CLpqv3nIC9HOGITkt1Kd-Am0n1LrdZvWwTo6RFe8AnzF0gpqjcB5Wg4Qeh58DIjZOz4f_8wnmJ_gCqyRh5vfSW4XHdbum0Tw`
const accessToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOlsidW5pdCIsInRlc3QiXSwiYmFyIjp7ImNvdW50IjoyMiwidGFncyI6WyJzb21lIiwidGFncyJdfSwiZXhwIjo0ODAyMjM4NjgyLCJmb28iOiJIZWxsbywgV29ybGQhIiwiaWF0IjoxNjc4MTAxMDIxLCJpc3MiOiJsb2NhbC5jb20iLCJqdGkiOiI5ODc2IiwibmJmIjoxNjc4MTAxMDIxLCJzdWIiOiJ0aW1AbG9jYWwuY29tIn0.Zrz3LWSRjCMJZUMaI5dUbW4vGdSmEeJQ3ouhaX0bcW9rdFFLgBI4K2FWJhNivq8JDmCGSxwLu3mI680GWmDaEoAx1M5sCO9lqfIZHGZh-lfAXk27e6FPLlkTDBq8Bx4o4DJ9Fw0hRJGjUTjnYv5cq1vo2-UqldasL6CwTbkzNC_4oQFfRtuodC4Ql7dZ1HRv5LXuYx7KPkOssLZtV9cwtJp5nFzKjcf2zEE_tlbjcpynMwypornRUp1EhCWKRUGkJhJeiP71ECY5pQhShfjBu9Nc5wDpSnZmnk2S4YsPrRK3QkE-iEkas8BfsOCrGoErHjEJexAIDjasGO5PFLWfCA`

func ExampleVerifyTokens_customClaims() {
	v := rp.NewIDTokenVerifier("local.com", "555666", tu.KeySet{},
		rp.WithNonce(func(ctx context.Context) string { return "12345" }),
	)

	// VerifyAccessToken can be called with the *MyCustomClaims.
	claims, err := rp.VerifyTokens[*MyCustomClaims](context.TODO(), accessToken, idToken, v)
	if err != nil {
		panic(err)
	}
	// Here we have typesafe access to the custom claims
	fmt.Println(claims.Foo, claims.Bar.Count, claims.Bar.Tags)
	// Output: Hello, World! 22 [some tags]
}
