package mock

import (
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func NewClient(t *testing.T) op.Client {
	return NewMockClient(gomock.NewController(t))
}

func NewClientExpectAny(t *testing.T, appType op.ApplicationType) op.Client {
	c := NewClient(t)
	m := c.(*MockClient)
	m.EXPECT().RedirectURIs().AnyTimes().Return([]string{
		"https://registered.com/callback",
		"http://registered.com/callback",
		"http://localhost:9999/callback",
		"custom://callback",
	})
	m.EXPECT().ApplicationType().AnyTimes().Return(appType)
	m.EXPECT().LoginURL(gomock.Any()).AnyTimes().DoAndReturn(
		func(id string) string {
			return "login?id=" + id
		})
	m.EXPECT().IsScopeAllowed(gomock.Any()).AnyTimes().Return(false)
	return c
}

func NewClientWithConfig(t *testing.T, uri []string, appType op.ApplicationType, responseTypes []oidc.ResponseType, devMode bool) op.Client {
	c := NewClient(t)
	m := c.(*MockClient)
	m.EXPECT().RedirectURIs().AnyTimes().Return(uri)
	m.EXPECT().ApplicationType().AnyTimes().Return(appType)
	m.EXPECT().ResponseTypes().AnyTimes().Return(responseTypes)
	m.EXPECT().DevMode().AnyTimes().Return(devMode)
	return c
}
