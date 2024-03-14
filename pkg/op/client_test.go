package op_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
	"github.com/zitadel/schema"
)

type testClientJWTProfile struct{}

func (testClientJWTProfile) JWTProfileVerifier(context.Context) *op.JWTProfileVerifier { return nil }

func TestClientJWTAuth(t *testing.T) {
	type args struct {
		ctx      context.Context
		ca       oidc.ClientAssertionParams
		verifier op.ClientJWTProfile
	}
	tests := []struct {
		name         string
		args         args
		wantClientID string
		wantErr      error
	}{
		{
			name: "empty assertion",
			args: args{
				context.Background(),
				oidc.ClientAssertionParams{},
				testClientJWTProfile{},
			},
			wantErr: op.ErrNoClientCredentials,
		},
		{
			name: "verification error",
			args: args{
				context.Background(),
				oidc.ClientAssertionParams{
					ClientAssertion: "foo",
				},
				testClientJWTProfile{},
			},
			wantErr: oidc.ErrParse,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClientID, err := op.ClientJWTAuth(tt.args.ctx, tt.args.ca, tt.args.verifier)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.wantClientID, gotClientID)
		})
	}
}

func TestClientBasicAuth(t *testing.T) {
	errWrong := errors.New("wrong secret")

	type args struct {
		username string
		password string
	}
	tests := []struct {
		name         string
		args         *args
		storage      op.Storage
		wantClientID string
		wantErr      error
	}{
		{
			name:    "no args",
			wantErr: op.ErrNoClientCredentials,
		},
		{
			name: "username unescape err",
			args: &args{
				username: "%",
				password: "bar",
			},
			wantErr: op.ErrInvalidAuthHeader,
		},
		{
			name: "password unescape err",
			args: &args{
				username: "foo",
				password: "%",
			},
			wantErr: op.ErrInvalidAuthHeader,
		},
		{
			name: "auth error",
			args: &args{
				username: "foo",
				password: "wrong",
			},
			storage: func() op.Storage {
				s := mock.NewMockStorage(gomock.NewController(t))
				s.EXPECT().AuthorizeClientIDSecret(gomock.Any(), "foo", "wrong").Return(errWrong)
				return s
			}(),
			wantErr: errWrong,
		},
		{
			name: "auth error",
			args: &args{
				username: "foo",
				password: "bar",
			},
			storage: func() op.Storage {
				s := mock.NewMockStorage(gomock.NewController(t))
				s.EXPECT().AuthorizeClientIDSecret(gomock.Any(), "foo", "bar").Return(nil)
				return s
			}(),
			wantClientID: "foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/foo", nil)
			if tt.args != nil {
				r.SetBasicAuth(tt.args.username, tt.args.password)
			}

			gotClientID, err := op.ClientBasicAuth(r, tt.storage)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.wantClientID, gotClientID)
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, io.ErrNoProgress
}

type testClientProvider struct {
	storage op.Storage
}

func (testClientProvider) Decoder() httphelper.Decoder {
	return schema.NewDecoder()
}

func (p testClientProvider) Storage() op.Storage {
	return p.storage
}

func TestClientIDFromRequest(t *testing.T) {
	type args struct {
		body io.Reader
		p    op.ClientProvider
	}
	type basicAuth struct {
		username string
		password string
	}
	tests := []struct {
		name              string
		args              args
		basicAuth         *basicAuth
		wantClientID      string
		wantAuthenticated bool
		wantErr           bool
	}{
		{
			name: "parse error",
			args: args{
				body: errReader{},
			},
			wantErr: true,
		},
		{
			name: "unauthenticated",
			args: args{
				body: strings.NewReader(
					url.Values{
						"client_id": []string{"foo"},
					}.Encode(),
				),
				p: testClientProvider{
					storage: mock.NewStorage(t),
				},
			},
			wantClientID:      "foo",
			wantAuthenticated: false,
		},
		{
			name: "authenticated",
			args: args{
				body: strings.NewReader(
					url.Values{}.Encode(),
				),
				p: testClientProvider{
					storage: func() op.Storage {
						s := mock.NewMockStorage(gomock.NewController(t))
						s.EXPECT().AuthorizeClientIDSecret(gomock.Any(), "foo", "bar").Return(nil)
						return s
					}(),
				},
			},
			basicAuth: &basicAuth{
				username: "foo",
				password: "bar",
			},
			wantClientID:      "foo",
			wantAuthenticated: true,
		},
		{
			name: "missing client id",
			args: args{
				body: strings.NewReader(
					url.Values{}.Encode(),
				),
				p: testClientProvider{
					storage: mock.NewStorage(t),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/foo", tt.args.body)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.basicAuth != nil {
				r.SetBasicAuth(tt.basicAuth.username, tt.basicAuth.password)
			}

			gotClientID, gotAuthenticated, err := op.ClientIDFromRequest(r, tt.args.p)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantClientID, gotClientID)
			assert.Equal(t, tt.wantAuthenticated, gotAuthenticated)
		})
	}
}
