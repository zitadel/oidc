package op_test

import (
	"crypto/rsa"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"

	"github.com/zitadel/oidc/pkg/oidc"
	"github.com/zitadel/oidc/pkg/op"
	"github.com/zitadel/oidc/pkg/op/mock"
)

func TestKeys(t *testing.T) {
	type args struct {
		k op.KeyProvider
	}
	type res struct {
		statusCode  int
		contentType string
		body        string
	}
	tests := []struct {
		name string
		args args
		res  res
	}{
		{
			name: "error",
			args: args{
				k: func() op.KeyProvider {
					m := mock.NewMockKeyProvider(gomock.NewController(t))
					m.EXPECT().GetKeySet(gomock.Any()).Return(nil, oidc.ErrServerError())
					return m
				}(),
			},
			res: res{
				statusCode:  http.StatusInternalServerError,
				contentType: "application/json",
				body: `{"error":"server_error"}
`,
			},
		},
		{
			name: "empty list",
			args: args{
				k: func() op.KeyProvider {
					m := mock.NewMockKeyProvider(gomock.NewController(t))
					m.EXPECT().GetKeySet(gomock.Any()).Return(nil, nil)
					return m
				}(),
			},
			res: res{
				statusCode:  http.StatusOK,
				contentType: "application/json",
			},
		},
		{
			name: "list",
			args: args{
				k: func() op.KeyProvider {
					m := mock.NewMockKeyProvider(gomock.NewController(t))
					m.EXPECT().GetKeySet(gomock.Any()).Return(
						&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
							{
								Key: &rsa.PublicKey{
									N: big.NewInt(1),
									E: 1,
								},
								KeyID: "id",
							},
						}},
						nil,
					)
					return m
				}(),
			},
			res: res{
				statusCode:  http.StatusOK,
				contentType: "application/json",
				body: `{"keys":[{"kty":"RSA","kid":"id","n":"AQ","e":"AQ"}]}
`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			op.Keys(w, httptest.NewRequest("GET", "/keys", nil), tt.args.k)
			assert.Equal(t, tt.res.statusCode, w.Result().StatusCode)
			assert.Equal(t, tt.res.contentType, w.Header().Get("content-type"))
			assert.Equal(t, tt.res.body, w.Body.String())
		})
	}
}
