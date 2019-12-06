package op

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/caos/oidc/pkg/oidc"
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
			Discover(tt.args.w, tt.args.config)
			rec := tt.args.w.(*httptest.ResponseRecorder)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, `{"issuer":"https://issuer.com"}`, rec.Body.String())
		})
	}
}

func TestCreateDiscoveryConfig(t *testing.T) {
	type args struct {
		c Configuration
		s Signer
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
			if got := CreateDiscoveryConfig(tt.args.c, tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateDiscoveryConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_scopes(t *testing.T) {
	type args struct {
		c Configuration
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
			if got := scopes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("scopes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_responseTypes(t *testing.T) {
	type args struct {
		c Configuration
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
			if got := responseTypes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("responseTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_grantTypes(t *testing.T) {
	type args struct {
		c Configuration
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
			if got := grantTypes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("grantTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}

// func Test_sigAlgorithms(t *testing.T) {
// 	type args struct {
// 		s Signer
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want []string
// 	}{
// 		{
// 			"",
// 			args{},
// 			[]string{"RS256"},
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := sigAlgorithms(tt.args.s); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("sigAlgorithms() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

// func Test_subjectTypes(t *testing.T) {
// 	type args struct {
// 		c Configuration
// 	}
// 	tests := []struct {
// 		name string
// 		args args
// 		want []string
// 	}{
// 		{
// 			"none",
// 			args{func()}
// 		}
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := subjectTypes(tt.args.c); !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("subjectTypes() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

func Test_authMethods(t *testing.T) {
	type args struct {
		basic bool
		post  bool
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			"none",
			args{false, false},
			[]string{},
		},
		{
			"basic",
			args{true, false},
			[]string{authMethodBasic},
		},
		{
			"post",
			args{false, true},
			[]string{authMethodPost},
		},
		{
			"basic and post",
			args{true, true},
			[]string{authMethodBasic, authMethodPost},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authMethods(tt.args.basic, tt.args.post); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authMethods() = %v, want %v", got, tt.want)
			}
		})
	}
}
