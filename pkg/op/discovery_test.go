package op_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
)

func TestDiscover(t *testing.T) {
	type args struct {
		w      http.ResponseWriter
		config *oidc.DiscoveryConfiguration
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"OK",
			args{
				httptest.NewRecorder(),
				&oidc.DiscoveryConfiguration{Issuer: "https://issuer.com"},
			},
			`{"issuer":"https://issuer.com","request_uri_parameter_supported":false}`,
		},
		{
			"client_id_metadata_document_supported",
			args{
				httptest.NewRecorder(),
				&oidc.DiscoveryConfiguration{
					Issuer:                            "https://issuer.com",
					ClientIDMetadataDocumentSupported: true,
				},
			},
			`{"issuer":"https://issuer.com","client_id_metadata_document_supported":true,"request_uri_parameter_supported":false}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.Discover(tt.args.w, tt.args.config)
			rec := tt.args.w.(*httptest.ResponseRecorder)
			require.Equal(t, http.StatusOK, rec.Code)
			require.JSONEq(t, tt.want, rec.Body.String())
		})
	}
}

func TestCreateDiscoveryConfig(t *testing.T) {
	type args struct {
		ctx context.Context
		c   op.Configuration
		s   op.DiscoverStorage
	}
	tests := []struct {
		name string
		args args
		want *oidc.DiscoveryConfiguration
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.CreateDiscoveryConfig(tt.args.ctx, tt.args.c, tt.args.s)
			assert.Equal(t, tt.want, got)
		})
	}
}

// scopeConfiguration is a minimal op.Configuration that is not a *op.Provider,
// used to verify that Scopes() honours any implementation advertising scopes.
// Only ScopesSupported is exercised, so the embedded interface stays nil.
type scopeConfiguration struct {
	op.Configuration
	scopes []string
}

func (c scopeConfiguration) ScopesSupported() []string { return c.scopes }

func Test_scopes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"default Scopes",
			args{},
			op.DefaultSupportedScopes,
		},
		{
			"custom scopes",
			args{newTestProvider(&op.Config{SupportedScopes: []string{"test1", "test2"}})},
			[]string{"test1", "test2"},
		},
		{
			// A Configuration advertising no scopes must fall back to the
			// defaults rather than an empty scopes_supported.
			"empty custom scopes",
			args{newTestProvider(&op.Config{SupportedScopes: []string{}})},
			op.DefaultSupportedScopes,
		},
		{
			"non-provider configuration advertising scopes",
			args{scopeConfiguration{scopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}}},
			[]string{oidc.ScopeOpenID, oidc.ScopeBoundKey},
		},
		{
			"non-provider configuration advertising no scopes",
			args{scopeConfiguration{}},
			op.DefaultSupportedScopes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.Scopes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDPoPSigningAlgorithms(t *testing.T) {
	assert.Nil(t, op.DPoPSigningAlgorithms(newTestProvider(&op.Config{})))
	assert.Equal(t,
		op.DPoPSigAlgorithms(op.DefaultDPoPSigningAlgs),
		op.DPoPSigningAlgorithms(newTestProvider(&op.Config{SupportedScopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}})),
	)
	assert.Empty(t, op.DPoPSigAlgorithms([]jose.SignatureAlgorithm{jose.HS256}))
}

func Test_ResponseTypes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"code and implicit flow",
			args{},
			[]string{"code", "id_token", "id_token token"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.ResponseTypes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_GrantTypes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.GrantType
	}{
		{
			"code and implicit flow",
			args{
				func() op.Configuration {
					c := mock.NewMockConfiguration(gomock.NewController(t))
					c.EXPECT().GrantTypeRefreshTokenSupported().Return(false)
					c.EXPECT().GrantTypeTokenExchangeSupported().Return(false)
					c.EXPECT().GrantTypeJWTAuthorizationSupported().Return(false)
					c.EXPECT().GrantTypeClientCredentialsSupported().Return(false)
					c.EXPECT().GrantTypeDeviceCodeSupported().Return(false)
					return c
				}(),
			},
			[]oidc.GrantType{
				oidc.GrantTypeCode,
				oidc.GrantTypeImplicit,
			},
		},
		{
			"code, implicit flow, refresh token, token exchange, jwt profile, client_credentials",
			args{
				func() op.Configuration {
					c := mock.NewMockConfiguration(gomock.NewController(t))
					c.EXPECT().GrantTypeRefreshTokenSupported().Return(true)
					c.EXPECT().GrantTypeTokenExchangeSupported().Return(true)
					c.EXPECT().GrantTypeJWTAuthorizationSupported().Return(true)
					c.EXPECT().GrantTypeClientCredentialsSupported().Return(true)
					c.EXPECT().GrantTypeDeviceCodeSupported().Return(false)
					return c
				}(),
			},
			[]oidc.GrantType{
				oidc.GrantTypeCode,
				oidc.GrantTypeImplicit,
				oidc.GrantTypeRefreshToken,
				oidc.GrantTypeClientCredentials,
				oidc.GrantTypeTokenExchange,
				oidc.GrantTypeBearer,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.GrantTypes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_SubjectTypes(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"none",
			args{},
			[]string{"public"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.SubjectTypes(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_SigAlgorithms(t *testing.T) {
	m := mock.NewMockDiscoverStorage(gomock.NewController(t))
	type args struct {
		s op.DiscoverStorage
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"",
			args{func() op.DiscoverStorage {
				m.EXPECT().SignatureAlgorithms(gomock.Any()).Return([]jose.SignatureAlgorithm{jose.RS256}, nil)
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.SigAlgorithms(context.Background(), tt.args.s)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_RequestObjectSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RequestObjectSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RequestObjectSupported().Return(true)
				m.EXPECT().RequestObjectSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().RequestObjectSupported().Return(true)
				m.EXPECT().RequestObjectSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.RequestObjectSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_AuthMethodsTokenEndpoint(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.AuthMethod
	}{
		{
			"none and basic",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(false)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic},
		},
		{
			"none, basic and post",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost},
		},
		{
			"none, basic, post and private_key_jwt",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodPrivateKeyJWT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.AuthMethodsTokenEndpoint(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_TokenSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().TokenEndpointSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().TokenEndpointSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.TokenSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_IntrospectionSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().IntrospectionAuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().IntrospectionAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().IntrospectionEndpointSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().IntrospectionAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().IntrospectionEndpointSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.IntrospectionSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_AuthMethodsIntrospectionEndpoint(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.AuthMethod
	}{
		{
			"basic only",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodBasic},
		},
		{
			"basic and private_key_jwt",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPrivateKeyJWT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.AuthMethodsIntrospectionEndpoint(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_RevocationSigAlgorithms(t *testing.T) {
	m := mock.NewMockConfiguration(gomock.NewController(t))
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"not supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RevocationAuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			nil,
		},
		{
			"supported, empty",
			args{func() op.Configuration {
				m.EXPECT().RevocationAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().RevocationEndpointSigningAlgorithmsSupported().Return(nil)
				return m
			}()},
			nil,
		},
		{
			"supported, list",
			args{func() op.Configuration {
				m.EXPECT().RevocationAuthMethodPrivateKeyJWTSupported().Return(true)
				m.EXPECT().RevocationEndpointSigningAlgorithmsSupported().Return([]string{"RS256"})
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.RevocationSigAlgorithms(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_AuthMethodsRevocationEndpoint(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.AuthMethod
	}{
		{
			"none and basic",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(false)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic},
		},
		{
			"none, basic and post",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(false)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost},
		},
		{
			"none, basic, post and private_key_jwt",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().AuthMethodPostSupported().Return(true)
				m.EXPECT().AuthMethodPrivateKeyJWTSupported().Return(true)
				return m
			}()},
			[]oidc.AuthMethod{oidc.AuthMethodNone, oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodPrivateKeyJWT},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.AuthMethodsRevocationEndpoint(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSupportedClaims(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"scopes",
			args{},
			[]string{
				"sub",
				"aud",
				"exp",
				"iat",
				"iss",
				"auth_time",
				"nonce",
				"acr",
				"amr",
				"c_hash",
				"at_hash",
				"act",
				"scopes",
				"client_id",
				"azp",
				"preferred_username",
				"name",
				"family_name",
				"given_name",
				"locale",
				"email",
				"email_verified",
				"phone_number",
				"phone_number_verified",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.SupportedClaims(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_CodeChallengeMethods(t *testing.T) {
	type args struct {
		c op.Configuration
	}
	tests := []struct {
		name string
		args args
		want []oidc.CodeChallengeMethod
	}{
		{
			"not supported",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().CodeMethodS256Supported().Return(false)
				return m
			}()},
			[]oidc.CodeChallengeMethod{},
		},
		{
			"S256",
			args{func() op.Configuration {
				m := mock.NewMockConfiguration(gomock.NewController(t))
				m.EXPECT().CodeMethodS256Supported().Return(true)
				return m
			}()},
			[]oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := op.CodeChallengeMethods(tt.args.c)
			assert.Equal(t, tt.want, got)
		})
	}
}

// nonDeviceStorage is an op.Storage that does not support the device_code grant,
// so WithKeyBinding has no device storage requirement to enforce.
type nonDeviceStorage struct{ op.Storage }

// deviceStorageWithoutBoundKey supports device_code but has not implemented the
// key-binding extension, which WithKeyBinding must reject at construction.
type deviceStorageWithoutBoundKey struct{ op.Storage }

func (deviceStorageWithoutBoundKey) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	return nil
}

func (deviceStorageWithoutBoundKey) GetDeviceAuthorizatonState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	return nil, nil
}

type deviceStorageWithBoundKey struct{ deviceStorageWithoutBoundKey }

func (deviceStorageWithBoundKey) StoreBoundKeyDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string, dpopJKT string) error {
	return nil
}

// TestWithKeyBinding covers the provider option: it must make discovery
// advertise the feature, must not mutate the caller's Config, and must reject a
// device-capable storage that cannot persist dpop_jkt.
func TestWithKeyBinding(t *testing.T) {
	newProvider := func(t *testing.T, config *op.Config, storage op.Storage, opts ...op.Option) (*op.Provider, error) {
		t.Helper()
		return op.NewOpenIDProvider(testIssuer, config, storage,
			append([]op.Option{op.WithAllowInsecure()}, opts...)...)
	}

	t.Run("advertises bound_key and DPoP algorithms", func(t *testing.T) {
		config := &op.Config{CryptoKey: testConfig.CryptoKey}
		provider, err := newProvider(t, config, nonDeviceStorage{}, op.WithKeyBinding())
		require.NoError(t, err)

		assert.Contains(t, provider.ScopesSupported(), oidc.ScopeBoundKey)
		assert.Equal(t, op.DPoPSigAlgorithms(nil), op.DPoPSigningAlgorithms(provider))
		// The caller's Config must be left alone.
		assert.Nil(t, config.SupportedScopes)
	})

	t.Run("disabled by default", func(t *testing.T) {
		provider, err := newProvider(t, &op.Config{CryptoKey: testConfig.CryptoKey}, nonDeviceStorage{})
		require.NoError(t, err)

		assert.NotContains(t, provider.ScopesSupported(), oidc.ScopeBoundKey)
		assert.Empty(t, op.DPoPSigningAlgorithms(provider))
	})

	t.Run("appends to custom scopes without duplicating", func(t *testing.T) {
		provider, err := newProvider(t,
			&op.Config{CryptoKey: testConfig.CryptoKey, SupportedScopes: []string{oidc.ScopeOpenID}},
			nonDeviceStorage{}, op.WithKeyBinding())
		require.NoError(t, err)
		assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, provider.ScopesSupported())

		// Already advertised explicitly: must not be added twice.
		provider, err = newProvider(t,
			&op.Config{CryptoKey: testConfig.CryptoKey, SupportedScopes: []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}},
			nonDeviceStorage{}, op.WithKeyBinding())
		require.NoError(t, err)
		assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeBoundKey}, provider.ScopesSupported())
	})

	t.Run("option order does not matter", func(t *testing.T) {
		first, err := newProvider(t, &op.Config{CryptoKey: testConfig.CryptoKey}, nonDeviceStorage{},
			op.WithKeyBinding(), op.WithCustomAuthEndpoint(op.NewEndpoint("auth")))
		require.NoError(t, err)
		second, err := newProvider(t, &op.Config{CryptoKey: testConfig.CryptoKey}, nonDeviceStorage{},
			op.WithCustomAuthEndpoint(op.NewEndpoint("auth")), op.WithKeyBinding())
		require.NoError(t, err)
		assert.Equal(t, first.ScopesSupported(), second.ScopesSupported())
	})

	t.Run("device storage without bound key support is rejected at construction", func(t *testing.T) {
		_, err := newProvider(t, &op.Config{CryptoKey: testConfig.CryptoKey},
			deviceStorageWithoutBoundKey{}, op.WithKeyBinding())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "BoundKeyDeviceAuthorizationStorage")
	})

	t.Run("device storage with bound key support is accepted", func(t *testing.T) {
		provider, err := newProvider(t, &op.Config{CryptoKey: testConfig.CryptoKey},
			deviceStorageWithBoundKey{}, op.WithKeyBinding())
		require.NoError(t, err)
		assert.Contains(t, provider.ScopesSupported(), oidc.ScopeBoundKey)
	})

	t.Run("device storage without bound key support is fine when not enabled", func(t *testing.T) {
		_, err := newProvider(t, &op.Config{CryptoKey: testConfig.CryptoKey}, deviceStorageWithoutBoundKey{})
		require.NoError(t, err)
	})
}
