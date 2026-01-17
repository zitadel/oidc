package op_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/schema"

	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
)

type revocationMTLSTestRevoker struct {
	decoder             httphelper.Decoder
	storage             op.Storage
	mtlsConfig          *op.MTLSConfig
	tlsSupported        bool
	selfSignedSupported bool
}

func (r *revocationMTLSTestRevoker) Decoder() httphelper.Decoder {
	return r.decoder
}

func (r *revocationMTLSTestRevoker) Crypto() op.Crypto {
	return nil
}

func (r *revocationMTLSTestRevoker) Storage() op.Storage {
	return r.storage
}

func (r *revocationMTLSTestRevoker) AccessTokenVerifier(context.Context) *op.AccessTokenVerifier {
	return nil
}

func (r *revocationMTLSTestRevoker) AuthMethodPrivateKeyJWTSupported() bool {
	return false
}

func (r *revocationMTLSTestRevoker) AuthMethodPostSupported() bool {
	return false
}

func (r *revocationMTLSTestRevoker) MTLSConfig() *op.MTLSConfig {
	return r.mtlsConfig
}

func (r *revocationMTLSTestRevoker) AuthMethodTLSClientAuthSupported() bool {
	return r.tlsSupported
}

func (r *revocationMTLSTestRevoker) AuthMethodSelfSignedTLSClientAuthSupported() bool {
	return r.selfSignedSupported
}

type mtlsTestClient struct {
	id              string
	authMethod      oidc.AuthMethod
	accessTokenType op.AccessTokenType
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	mtlsConfig      *op.MTLSClientConfig
	registeredCerts []string
}

func (c *mtlsTestClient) GetID() string {
	return c.id
}

func (c *mtlsTestClient) RedirectURIs() []string {
	return nil
}

func (c *mtlsTestClient) PostLogoutRedirectURIs() []string {
	return nil
}

func (c *mtlsTestClient) ApplicationType() op.ApplicationType {
	return op.ApplicationTypeWeb
}

func (c *mtlsTestClient) AuthMethod() oidc.AuthMethod {
	return c.authMethod
}

func (c *mtlsTestClient) ResponseTypes() []oidc.ResponseType {
	return c.responseTypes
}

func (c *mtlsTestClient) GrantTypes() []oidc.GrantType {
	return c.grantTypes
}

func (c *mtlsTestClient) LoginURL(id string) string {
	return ""
}

func (c *mtlsTestClient) AccessTokenType() op.AccessTokenType {
	return c.accessTokenType
}

func (c *mtlsTestClient) IDTokenLifetime() time.Duration {
	return time.Minute
}

func (c *mtlsTestClient) DevMode() bool {
	return false
}

func (c *mtlsTestClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *mtlsTestClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *mtlsTestClient) IsScopeAllowed(string) bool {
	return true
}

func (c *mtlsTestClient) IDTokenUserinfoClaimsAssertion() bool {
	return false
}

func (c *mtlsTestClient) ClockSkew() time.Duration {
	return 0
}

func (c *mtlsTestClient) GetMTLSConfig() *op.MTLSClientConfig {
	return c.mtlsConfig
}

func (c *mtlsTestClient) GetRegisteredCertificates() []string {
	return c.registeredCerts
}

func newTestDecoder() *schema.Decoder {
	dec := schema.NewDecoder()
	dec.IgnoreUnknownKeys(true)
	return dec
}

func TestParseTokenRevocationRequest_MTLSClientAuth_Success(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client1"},
		parent:    ca,
		parentKey: caKey,
	})

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	client := &mtlsTestClient{
		id:              "client1",
		authMethod:      oidc.AuthMethodTLSClientAuth,
		accessTokenType: op.AccessTokenTypeJWT,
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:      []oidc.GrantType{oidc.GrantTypeCode},
		mtlsConfig:      &op.MTLSClientConfig{SubjectDN: "CN=client1"},
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	storage := mock.NewMockStorage(ctrl)
	storage.EXPECT().GetClientByClientID(gomock.Any(), "client1").Return(client, nil)

	revoker := &revocationMTLSTestRevoker{
		decoder:      newTestDecoder(),
		storage:      storage,
		mtlsConfig:   &op.MTLSConfig{TrustStore: pool},
		tlsSupported: true,
	}

	r := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader("token=foo&client_id=client1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}

	token, hint, clientID, err := op.ParseTokenRevocationRequest(r, revoker)
	require.NoError(t, err)
	require.Equal(t, "foo", token)
	require.Empty(t, hint)
	require.Equal(t, "client1", clientID)
}

func TestParseTokenRevocationRequest_MTLSClientAuth_NoCert(t *testing.T) {
	ca, _ := generateTestCA(t, pkix.Name{CommonName: "Test CA"})
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	client := &mtlsTestClient{
		id:              "client1",
		authMethod:      oidc.AuthMethodTLSClientAuth,
		accessTokenType: op.AccessTokenTypeJWT,
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:      []oidc.GrantType{oidc.GrantTypeCode},
		mtlsConfig:      &op.MTLSClientConfig{SubjectDN: "CN=client1"},
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	storage := mock.NewMockStorage(ctrl)
	storage.EXPECT().GetClientByClientID(gomock.Any(), "client1").Return(client, nil)

	revoker := &revocationMTLSTestRevoker{
		decoder:      newTestDecoder(),
		storage:      storage,
		mtlsConfig:   &op.MTLSConfig{TrustStore: pool},
		tlsSupported: true,
	}

	r := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader("token=foo&client_id=client1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, _, _, err := op.ParseTokenRevocationRequest(r, revoker)
	require.Error(t, err)

	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	require.Equal(t, oidc.InvalidClient, oidcErr.ErrorType)
}

func TestParseTokenRevocationRequest_SelfSignedTLSClientAuth_Success(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client1"},
	})

	client := &mtlsTestClient{
		id:              "client1",
		authMethod:      oidc.AuthMethodSelfSignedTLSClientAuth,
		accessTokenType: op.AccessTokenTypeJWT,
		responseTypes:   []oidc.ResponseType{oidc.ResponseTypeCode},
		grantTypes:      []oidc.GrantType{oidc.GrantTypeCode},
		registeredCerts: []string{certToPEM(clientCert)},
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	storage := mock.NewMockStorage(ctrl)
	storage.EXPECT().GetClientByClientID(gomock.Any(), "client1").Return(client, nil)

	revoker := &revocationMTLSTestRevoker{
		decoder:             newTestDecoder(),
		storage:             storage,
		mtlsConfig:          &op.MTLSConfig{},
		selfSignedSupported: true,
	}

	r := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader("token=foo&client_id=client1"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}

	token, hint, clientID, err := op.ParseTokenRevocationRequest(r, revoker)
	require.NoError(t, err)
	require.Equal(t, "foo", token)
	require.Empty(t, hint)
	require.Equal(t, "client1", clientID)
}
