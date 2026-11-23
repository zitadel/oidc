package op_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tu "github.com/zitadel/oidc/v3/internal/testutil"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/op/mock"
	"github.com/zitadel/schema"
)

type testClientJWTProfile struct{}

func (testClientJWTProfile) JWTProfileVerifier(context.Context) *op.JWTProfileVerifier { return nil }

// keyErrJWTProfile verifies JWT assertions with a key storage that fails with err.
type keyErrJWTProfile struct {
	err error
}

func (p keyErrJWTProfile) JWTProfileVerifier(context.Context) *op.JWTProfileVerifier {
	return op.NewJWTProfileVerifier(p, tu.ValidIssuer, time.Minute, 0)
}

func (p keyErrJWTProfile) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, p.err
}

// assertErrorType asserts that err is an *oidc.Error of type wantType.
// require.ErrorIs alone cannot tell the error type, as it also matches a
// Storage error that is the parent of another type.
func assertErrorType(t *testing.T, err error, wantType string) {
	t.Helper()
	if wantType == "" {
		return
	}
	var oidcErr *oidc.Error
	require.ErrorAs(t, err, &oidcErr)
	assert.Equal(t, wantType, string(oidcErr.ErrorType))
}

func TestClientJWTAuth(t *testing.T) {
	errKey := errors.New("key not found")
	errDB := errors.New("db down")
	assertion, _ := tu.ValidJWTProfileAssertion()

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
		wantType     string
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
		{
			name: "key storage error",
			args: args{
				context.Background(),
				oidc.ClientAssertionParams{ClientAssertion: assertion},
				keyErrJWTProfile{err: errKey},
			},
			wantErr:  errKey,
			wantType: string(oidc.UnauthorizedClient),
		},
		{
			name: "key storage server_error",
			args: args{
				context.Background(),
				oidc.ClientAssertionParams{ClientAssertion: assertion},
				keyErrJWTProfile{err: oidc.ErrServerError().WithParent(errDB)},
			},
			wantErr:  errDB,
			wantType: string(oidc.ServerError),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClientID, err := op.ClientJWTAuth(tt.args.ctx, tt.args.ca, tt.args.verifier)
			require.ErrorIs(t, err, tt.wantErr)
			assertErrorType(t, err, tt.wantType)
			assert.Equal(t, tt.wantClientID, gotClientID)
		})
	}
}

func TestClientBasicAuth(t *testing.T) {
	errWrong := errors.New("wrong secret")
	errDB := errors.New("db down")
	errTypedNil := fmt.Errorf("authorize: %w", (*oidc.Error)(nil))
	errClient := oidc.ErrInvalidClient()
	errTimeout := fmt.Errorf("authorize: %w", errors.Join(oidc.ErrServerError(), context.DeadlineExceeded))
	failingStorage := func(err error) op.Storage {
		s := mock.NewMockStorage(gomock.NewController(t))
		s.EXPECT().AuthorizeClientIDSecret(gomock.Any(), "foo", "bar").Return(err)
		return s
	}

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
		wantType     string
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
			wantErr:  errWrong,
			wantType: string(oidc.UnauthorizedClient),
		},
		{
			name:     "storage server_error",
			args:     &args{username: "foo", password: "bar"},
			storage:  failingStorage(oidc.ErrServerError().WithParent(errDB)),
			wantErr:  errDB,
			wantType: string(oidc.ServerError),
		},
		{
			name:     "storage server_error keeps the error chain",
			args:     &args{username: "foo", password: "bar"},
			storage:  failingStorage(errTimeout),
			wantErr:  context.DeadlineExceeded,
			wantType: string(oidc.ServerError),
		},
		{
			name:     "storage client error stays wrapped",
			args:     &args{username: "foo", password: "bar"},
			storage:  failingStorage(errClient),
			wantErr:  errClient,
			wantType: string(oidc.UnauthorizedClient),
		},
		{
			name:     "storage typed nil oidc error",
			args:     &args{username: "foo", password: "bar"},
			storage:  failingStorage(errTypedNil),
			wantErr:  errTypedNil,
			wantType: string(oidc.UnauthorizedClient),
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
			assertErrorType(t, err, tt.wantType)
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
