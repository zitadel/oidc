package op_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/pkg/oidc"
	"github.com/zitadel/oidc/pkg/op"
	"github.com/zitadel/oidc/pkg/op/mock"
)

func TestDiscover(t *testing.T) {
	type args struct {
		w      http.ResponseWriter
		config *oidc.DiscoveryConfiguration
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"OK",
			args{
				httptest.NewRecorder(),
				&oidc.DiscoveryConfiguration{Issuer: "https://issuer.com"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op.Discover(tt.args.w, tt.args.config)
			rec := tt.args.w.(*httptest.ResponseRecorder)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t,
				`{"issuer":"https://issuer.com","request_uri_parameter_supported":false}
`,
				rec.Body.String())
		})
	}
}

func TestCreateDiscoveryConfig(t *testing.T) {
	type args struct {
		c op.Configuration
		s op.Signer
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
			if got := op.CreateDiscoveryConfig(tt.args.c, tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateDiscoveryConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.Scopes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("scopes() = %v, want %v", got, tt.want)
			}
		})
	}
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.ResponseTypes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("responseTypes() = %v, want %v", got, tt.want)
			}
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
		want []string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.GrantTypes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("grantTypes() = %v, want %v", got, tt.want)
			}
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.SupportedClaims(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SupportedClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_SigAlgorithms(t *testing.T) {
	m := mock.NewMockSigner(gomock.NewController(t))
	type args struct {
		s op.Signer
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"",
			args{func() op.Signer {
				m.EXPECT().SignatureAlgorithm().Return(jose.RS256)
				return m
			}()},
			[]string{"RS256"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := op.SigAlgorithms(tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sigAlgorithms() = %v, want %v", got, tt.want)
			}
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
			if got := op.SubjectTypes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("subjectTypes() = %v, want %v", got, tt.want)
			}
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
			if got := op.AuthMethodsTokenEndpoint(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authMethods() = %v, want %v", got, tt.want)
			}
		})
	}
}
