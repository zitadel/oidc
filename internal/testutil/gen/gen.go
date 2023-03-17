// Package gen allows generating of example tokens and claims.
//
//	go run ./internal/testutil/gen
package main

import (
	"encoding/json"
	"fmt"
	"os"

	tu "github.com/zitadel/oidc/v3/internal/testutil"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var custom = map[string]any{
	"foo": "Hello, World!",
	"bar": struct {
		Count int      `json:"count,omitempty"`
		Tags  []string `json:"tags,omitempty"`
	}{
		Count: 22,
		Tags:  []string{"some", "tags"},
	},
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "    ")

	accessToken, atClaims := tu.NewAccessTokenCustom(
		tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
		tu.ValidExpiration.AddDate(99, 0, 0), tu.ValidJWTID,
		tu.ValidClientID, tu.ValidSkew, custom,
	)
	atHash, err := oidc.ClaimHash(accessToken, tu.SignatureAlgorithm)
	if err != nil {
		panic(err)
	}

	idToken, idClaims := tu.NewIDTokenCustom(
		tu.ValidIssuer, tu.ValidSubject, tu.ValidAudience,
		tu.ValidExpiration.AddDate(99, 0, 0), tu.ValidAuthTime,
		tu.ValidNonce, tu.ValidACR, tu.ValidAMR, tu.ValidClientID,
		tu.ValidSkew, atHash, custom,
	)

	fmt.Println("access token claims:")
	if err := enc.Encode(atClaims); err != nil {
		panic(err)
	}
	fmt.Printf("access token:\n%s\n", accessToken)

	fmt.Println("ID token claims:")
	if err := enc.Encode(idClaims); err != nil {
		panic(err)
	}
	fmt.Printf("ID token:\n%s\n", idToken)
}
