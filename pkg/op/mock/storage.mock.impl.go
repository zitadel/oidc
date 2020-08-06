package mock

import (
	"context"
	"errors"
	"github.com/caos/oidc/pkg/oidc"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/golang/mock/gomock"

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

func NewMockStorageExpectInvalidClientID(t *testing.T) op.Storage {
	m := NewStorage(t)
	ExpectInvalidClientID(m)
	return m
}

func NewMockStorageAny(t *testing.T) op.Storage {
	m := NewStorage(t)
	mockS := m.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any(), gomock.Any()).AnyTimes().Return(&ConfClient{}, nil)
	mockS.EXPECT().AuthorizeClientIDSecret(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	return m
}

func NewMockStorageSigningKeyError(t *testing.T) op.Storage {
	m := NewStorage(t)
	ExpectSigningKeyError(m)
	return m
}

func NewMockStorageSigningKeyInvalid(t *testing.T) op.Storage {
	m := NewStorage(t)
	ExpectSigningKeyInvalid(m)
	return m
}
func NewMockStorageSigningKey(t *testing.T) op.Storage {
	m := NewStorage(t)
	ExpectSigningKey(m)
	return m
}

func ExpectInvalidClientID(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any(), gomock.Any()).Return(nil, errors.New("client not found"))
}

func ExpectValidClientID(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetClientByClientID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, id string) (op.Client, error) {
			var appType op.ApplicationType
			var authMethod op.AuthMethod
			var accessTokenType op.AccessTokenType
			var responseTypes []oidc.ResponseType
			switch id {
			case "web_client":
				appType = op.ApplicationTypeWeb
				authMethod = op.AuthMethodBasic
				accessTokenType = op.AccessTokenTypeBearer
				responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
			case "native_client":
				appType = op.ApplicationTypeNative
				authMethod = op.AuthMethodNone
				accessTokenType = op.AccessTokenTypeBearer
				responseTypes = []oidc.ResponseType{oidc.ResponseTypeCode}
			case "useragent_client":
				appType = op.ApplicationTypeUserAgent
				authMethod = op.AuthMethodBasic
				accessTokenType = op.AccessTokenTypeJWT
				responseTypes = []oidc.ResponseType{oidc.ResponseTypeIDToken}
			}
			return &ConfClient{id: id, appType: appType, authMethod: authMethod, accessTokenType: accessTokenType, responseTypes: responseTypes}, nil
		})
}

func ExpectSigningKeyError(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetSigningKey(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, keyCh chan<- jose.SigningKey, errCh chan<- error, _ <-chan bool) {
			errCh <- errors.New("error")
		},
	)
}

func ExpectSigningKeyInvalid(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetSigningKey(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, keyCh chan<- jose.SigningKey, errCh chan<- error, _ <-chan bool) {
			keyCh <- jose.SigningKey{}
		},
	)
}

func ExpectSigningKey(s op.Storage) {
	mockS := s.(*MockStorage)
	mockS.EXPECT().GetSigningKey(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, keyCh chan<- jose.SigningKey, errCh chan<- error, _ <-chan bool) {
			keyCh <- jose.SigningKey{Algorithm: jose.HS256, Key: []byte("key")}
		},
	)
}

type ConfClient struct {
	id              string
	appType         op.ApplicationType
	authMethod      op.AuthMethod
	accessTokenType op.AccessTokenType
	responseTypes   []oidc.ResponseType
	devMode         bool
}

func (c *ConfClient) RedirectURIs() []string {
	return []string{
		"https://registered.com/callback",
		"http://registered.com/callback",
		"http://localhost:9999/callback",
		"custom://callback",
	}
}
func (c *ConfClient) PostLogoutRedirectURIs() []string {
	return []string{}
}

func (c *ConfClient) LoginURL(id string) string {
	return "login?id=" + id
}

func (c *ConfClient) ApplicationType() op.ApplicationType {
	return c.appType
}

func (c *ConfClient) AuthMethod() op.AuthMethod {
	return c.authMethod
}

func (c *ConfClient) GetID() string {
	return c.id
}

func (c *ConfClient) AccessTokenLifetime() time.Duration {
	return time.Duration(5 * time.Minute)
}
func (c *ConfClient) IDTokenLifetime() time.Duration {
	return time.Duration(5 * time.Minute)
}
func (c *ConfClient) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}
func (c *ConfClient) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}
func (c *ConfClient) DevMode() bool {
	return c.devMode
}
