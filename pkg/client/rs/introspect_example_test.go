package rs_test

import (
	"context"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type IntrospectionResponse struct {
	Active     bool                     `json:"active"`
	Scope      oidc.SpaceDelimitedArray `json:"scope,omitempty"`
	ClientID   string                   `json:"client_id,omitempty"`
	TokenType  string                   `json:"token_type,omitempty"`
	Expiration oidc.Time                `json:"exp,omitempty"`
	IssuedAt   oidc.Time                `json:"iat,omitempty"`
	NotBefore  oidc.Time                `json:"nbf,omitempty"`
	Subject    string                   `json:"sub,omitempty"`
	Audience   oidc.Audience            `json:"aud,omitempty"`
	Issuer     string                   `json:"iss,omitempty"`
	JWTID      string                   `json:"jti,omitempty"`
	Username   string                   `json:"username,omitempty"`
	oidc.UserInfoProfile
	oidc.UserInfoEmail
	oidc.UserInfoPhone
	Address *oidc.UserInfoAddress `json:"address,omitempty"`

	// Foo and Bar are custom claims
	Foo string `json:"foo,omitempty"`
	Bar struct {
		Val1 string `json:"val_1,omitempty"`
		Val2 string `json:"val_2,omitempty"`
	} `json:"bar,omitempty"`

	// Claims are all the combined claims, including custom.
	Claims map[string]any `json:"-,omitempty"`
}

func ExampleIntrospect_custom() {
	rss, err := rs.NewResourceServerClientCredentials(context.TODO(), "http://localhost:8080", "clientid", "clientsecret")
	if err != nil {
		panic(err)
	}

	resp, err := rs.Introspect[*IntrospectionResponse](context.TODO(), rss, "accesstokenstring")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp)
}
