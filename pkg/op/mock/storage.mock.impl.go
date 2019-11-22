package mock

import (
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/caos/oidc/pkg/oidc"
	"github.com/caos/oidc/pkg/op"
)

func NewStorage(t *testing.T) op.Storage {
	return NewMockStorage(gomock.NewController(t))
}

func NewMockStorageExpectValidClientID(t *testing.T) op.Storage {
	m := NewStorage(t)
	ExpectValidClientID(m)
	return m
}

func NewMockStorageAny(t *testing.T) op.Storage {
	m := NewStorage(t)
	mockS := m.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any()).AnyTimes().Return(&ConfClient{}, nil)
	mockS.EXPECT().AuthorizeClientIDSecret(gomock.Any(), gomock.Any()).AnyTimes().Return(&ConfClient{}, nil)
	return m
}

func ExpectValidClientID(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any()).Return(&ConfClient{}, nil)
}

type ConfClient struct{}

func (c *ConfClient) Type() oidc.ClientType {
	return oidc.ClientTypeConfidential
}
func (c *ConfClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://localhost:9999/callback",
		"custom://callback",
	}
}

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}
