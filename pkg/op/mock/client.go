package mock

import (
	"testing"

	gomock "github.com/golang/mock/gomock"

	op "github.com/caos/oidc/pkg/op"
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
		"custom://callback"})
	m.EXPECT().ApplicationType().AnyTimes().Return(appType)
	m.EXPECT().LoginURL(gomock.Any()).AnyTimes().DoAndReturn(
		func(id string) string {
			return "login?id=" + id
		})
	return c
}
