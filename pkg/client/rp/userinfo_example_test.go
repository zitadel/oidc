package rp_test

import (
	"context"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type UserInfo struct {
	Subject string `json:"sub,omitempty"`
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

func (u *UserInfo) GetSubject() string {
	return u.Subject
}

func ExampleUserinfo_custom() {
	rpo, err := rp.NewRelyingPartyOIDC(context.TODO(), "http://localhost:8080", "clientid", "clientsecret", "http://example.com/redirect", []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone})
	if err != nil {
		panic(err)
	}

	info, err := rp.Userinfo[*UserInfo](context.TODO(), "accesstokenstring", "Bearer", "userid", rpo)
	if err != nil {
		panic(err)
	}

	fmt.Println(info)
}
