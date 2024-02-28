package op

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/schema"
)

func TestAuthRequestError(t *testing.T) {
	type args struct {
		authReq ErrAuthRequest
		err     error
	}
	tests := []struct {
		name        string
		args        args
		wantCode    int
		wantHeaders map[string]string
		wantBody    string
		wantLog     string
	}{
		{
			name: "nil auth request",
			args: args{
				authReq: nil,
				err:     io.ErrClosedPipe,
			},
			wantCode: http.StatusBadRequest,
			wantBody: "io: read/write on closed pipe\n",
			wantLog: `{
				"level":"ERROR",
				"msg":"auth request",
				"time":"not",
				"oidc_error":{
					"description":"io: read/write on closed pipe",
					"parent":"io: read/write on closed pipe",
					"type":"server_error"
				}
			}`,
		},
		{
			name: "auth request, no redirect URI",
			args: args{
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				err: oidc.ErrInteractionRequired().WithDescription("sign in"),
			},
			wantCode: http.StatusBadRequest,
			wantBody: "sign in\n",
			wantLog: `{
				"level":"WARN",
				"msg":"auth request: not redirecting",
				"time":"not",
				"auth_request":{
					"client_id":"123",
					"redirect_uri":"",
					"response_type":"responseType",
					"scopes":"a b"
				},
				"oidc_error":{
					"description":"sign in",
					"type":"interaction_required"
				}
			}`,
		},
		{
			name: "auth request, redirect disabled",
			args: args{
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					RedirectURI:  "http://example.com/callback",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				err: oidc.ErrInvalidRequestRedirectURI().WithDescription("oops"),
			},
			wantCode: http.StatusBadRequest,
			wantBody: "oops\n",
			wantLog: `{
				"level":"WARN",
				"msg":"auth request: not redirecting",
				"time":"not",
				"auth_request":{
					"client_id":"123",
					"redirect_uri":"http://example.com/callback",
					"response_type":"responseType",
					"scopes":"a b"
				},
				"oidc_error":{
					"description":"oops",
					"type":"invalid_request",
					"redirect_disabled":true
				}
			}`,
		},
		{
			name: "auth request, url parse error",
			args: args{
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					RedirectURI:  "can't parse this!\n",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				err: oidc.ErrInteractionRequired().WithDescription("sign in"),
			},
			wantCode: http.StatusBadRequest,
			wantBody: "ErrorType=server_error Parent=parse \"can't parse this!\\n\": net/url: invalid control character in URL\n",
			wantLog: `{
					"level":"ERROR",
					"msg":"auth response URL",
					"time":"not",
					"auth_request":{
						"client_id":"123",
						"redirect_uri":"can't parse this!\n",
						"response_type":"responseType",
						"scopes":"a b"
					},
					"error":{
						"type":"server_error",
						"parent":"parse \"can't parse this!\\n\": net/url: invalid control character in URL"
					},
					"oidc_error":{
						"description":"sign in",
						"type":"interaction_required"
					}
				}`,
		},
		{
			name: "auth request redirect",
			args: args{
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					RedirectURI:  "http://example.com/callback",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				err: oidc.ErrInteractionRequired().WithDescription("sign in"),
			},
			wantCode:    http.StatusFound,
			wantHeaders: map[string]string{"Location": "http://example.com/callback?error=interaction_required&error_description=sign+in&state=state1"},
			wantLog: `{
					"level":"WARN",
					"msg":"auth request",
					"time":"not",
					"auth_request":{
						"client_id":"123",
						"redirect_uri":"http://example.com/callback",
						"response_type":"responseType",
						"scopes":"a b"
					},
					"oidc_error":{
						"description":"sign in",
						"type":"interaction_required"
					}
				}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOut := new(strings.Builder)
			authorizer := &Provider{
				encoder: schema.NewEncoder(),
				logger: slog.New(
					slog.NewJSONHandler(logOut, &slog.HandlerOptions{
						Level: slog.LevelInfo,
					}).WithAttrs([]slog.Attr{slog.String("time", "not")}),
				),
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/path", nil)
			AuthRequestError(w, r, tt.args.authReq, tt.args.err, authorizer)

			res := w.Result()
			defer res.Body.Close()

			assert.Equal(t, tt.wantCode, res.StatusCode)
			for key, wantHeader := range tt.wantHeaders {
				gotHeader := res.Header.Get(key)
				assert.Equalf(t, wantHeader, gotHeader, "header %q", key)
			}
			gotBody, err := io.ReadAll(res.Body)
			require.NoError(t, err, "read result body")
			assert.Equal(t, tt.wantBody, string(gotBody), "result body")

			gotLog := logOut.String()
			t.Log(gotLog)
			assert.JSONEq(t, tt.wantLog, gotLog, "log output")
		})
	}
}

func TestRequestError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
		wantLog  string
	}{
		{
			name:     "server error",
			err:      io.ErrClosedPipe,
			wantCode: http.StatusBadRequest,
			wantBody: `{"error":"server_error", "error_description":"io: read/write on closed pipe"}`,
			wantLog: `{
				"level":"ERROR",
				"msg":"request error",
				"time":"not",
				"oidc_error":{
					"parent":"io: read/write on closed pipe",
					"description":"io: read/write on closed pipe",
					"type":"server_error"}
				}`,
		},
		{
			name:     "invalid client",
			err:      oidc.ErrInvalidClient().WithDescription("not good"),
			wantCode: http.StatusUnauthorized,
			wantBody: `{"error":"invalid_client", "error_description":"not good"}`,
			wantLog: `{
				"level":"WARN",
				"msg":"request error",
				"time":"not",
				"oidc_error":{
					"description":"not good",
					"type":"invalid_client"}
				}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOut := new(strings.Builder)
			logger := slog.New(
				slog.NewJSONHandler(logOut, &slog.HandlerOptions{
					Level: slog.LevelInfo,
				}).WithAttrs([]slog.Attr{slog.String("time", "not")}),
			)
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/path", nil)
			RequestError(w, r, tt.err, logger)

			res := w.Result()
			defer res.Body.Close()

			assert.Equal(t, tt.wantCode, res.StatusCode, "status code")

			gotBody, err := io.ReadAll(res.Body)
			require.NoError(t, err, "read result body")
			assert.JSONEq(t, tt.wantBody, string(gotBody), "result body")

			gotLog := logOut.String()
			t.Log(gotLog)
			assert.JSONEq(t, tt.wantLog, gotLog, "log output")
		})
	}
}

func TestTryErrorRedirect(t *testing.T) {
	type args struct {
		ctx     context.Context
		authReq ErrAuthRequest
		parent  error
	}
	tests := []struct {
		name    string
		args    args
		want    *Redirect
		wantErr error
		wantLog string
	}{
		{
			name: "nil auth request",
			args: args{
				ctx:     context.Background(),
				authReq: nil,
				parent:  io.ErrClosedPipe,
			},
			wantErr: NewStatusError(io.ErrClosedPipe, http.StatusBadRequest),
			wantLog: `{
				"level":"ERROR",
				"msg":"auth request",
				"time":"not",
				"oidc_error":{
					"description":"io: read/write on closed pipe",
					"parent":"io: read/write on closed pipe",
					"type":"server_error"
				}
			}`,
		},
		{
			name: "auth request, no redirect URI",
			args: args{
				ctx: context.Background(),
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				parent: oidc.ErrInteractionRequired().WithDescription("sign in"),
			},
			wantErr: NewStatusError(oidc.ErrInteractionRequired().WithDescription("sign in"), http.StatusBadRequest),
			wantLog: `{
				"level":"WARN",
				"msg":"auth request: not redirecting",
				"time":"not",
				"auth_request":{
					"client_id":"123",
					"redirect_uri":"",
					"response_type":"responseType",
					"scopes":"a b"
				},
				"oidc_error":{
					"description":"sign in",
					"type":"interaction_required"
				}
			}`,
		},
		{
			name: "auth request, redirect disabled",
			args: args{
				ctx: context.Background(),
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					RedirectURI:  "http://example.com/callback",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				parent: oidc.ErrInvalidRequestRedirectURI().WithDescription("oops"),
			},
			wantErr: NewStatusError(oidc.ErrInvalidRequestRedirectURI().WithDescription("oops"), http.StatusBadRequest),
			wantLog: `{
				"level":"WARN",
				"msg":"auth request: not redirecting",
				"time":"not",
				"auth_request":{
					"client_id":"123",
					"redirect_uri":"http://example.com/callback",
					"response_type":"responseType",
					"scopes":"a b"
				},
				"oidc_error":{
					"description":"oops",
					"type":"invalid_request",
					"redirect_disabled":true
				}
			}`,
		},
		{
			name: "auth request, url parse error",
			args: args{
				ctx: context.Background(),
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					RedirectURI:  "can't parse this!\n",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				parent: oidc.ErrInteractionRequired().WithDescription("sign in"),
			},
			wantErr: func() error {
				//lint:ignore SA1007 just recreating the error for testing
				_, err := url.Parse("can't parse this!\n")
				err = oidc.ErrServerError().WithParent(err)
				return NewStatusError(err, http.StatusBadRequest)
			}(),
			wantLog: `{
					"level":"ERROR",
					"msg":"auth response URL",
					"time":"not",
					"auth_request":{
						"client_id":"123",
						"redirect_uri":"can't parse this!\n",
						"response_type":"responseType",
						"scopes":"a b"
					},
					"error":{
						"type":"server_error",
						"parent":"parse \"can't parse this!\\n\": net/url: invalid control character in URL"
					},
					"oidc_error":{
						"description":"sign in",
						"type":"interaction_required"
					}
				}`,
		},
		{
			name: "auth request redirect",
			args: args{
				ctx: context.Background(),
				authReq: &oidc.AuthRequest{
					Scopes:       oidc.SpaceDelimitedArray{"a", "b"},
					ResponseType: "responseType",
					ClientID:     "123",
					RedirectURI:  "http://example.com/callback",
					State:        "state1",
					ResponseMode: oidc.ResponseModeQuery,
				},
				parent: oidc.ErrInteractionRequired().WithDescription("sign in"),
			},
			want: &Redirect{
				URL: "http://example.com/callback?error=interaction_required&error_description=sign+in&state=state1",
			},
			wantLog: `{
						"level":"WARN",
						"msg":"auth request redirect",
						"time":"not",
						"auth_request":{
							"client_id":"123",
							"redirect_uri":"http://example.com/callback",
							"response_type":"responseType",
							"scopes":"a b"
						},
						"oidc_error":{
							"description":"sign in",
							"type":"interaction_required"
						},
						"url":"http://example.com/callback?error=interaction_required&error_description=sign+in&state=state1"
					}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOut := new(strings.Builder)
			logger := slog.New(
				slog.NewJSONHandler(logOut, &slog.HandlerOptions{
					Level: slog.LevelInfo,
				}).WithAttrs([]slog.Attr{slog.String("time", "not")}),
			)
			encoder := schema.NewEncoder()

			got, err := TryErrorRedirect(tt.args.ctx, tt.args.authReq, tt.args.parent, encoder, logger)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)

			gotLog := logOut.String()
			t.Log(gotLog)
			assert.JSONEq(t, tt.wantLog, gotLog, "log output")
		})
	}
}

func TestNewStatusError(t *testing.T) {
	err := NewStatusError(io.ErrClosedPipe, http.StatusInternalServerError)

	want := "Internal Server Error: io: read/write on closed pipe"
	got := fmt.Sprint(err)
	assert.Equal(t, want, got)
}

func TestAsStatusError(t *testing.T) {
	type args struct {
		err        error
		statusCode int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "already status error",
			args: args{
				err:        NewStatusError(io.ErrClosedPipe, http.StatusInternalServerError),
				statusCode: http.StatusBadRequest,
			},
			want: "Internal Server Error: io: read/write on closed pipe",
		},
		{
			name: "oidc error",
			args: args{
				err:        oidc.ErrAcrInvalid,
				statusCode: http.StatusBadRequest,
			},
			want: "Bad Request: acr is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := AsStatusError(tt.args.err, tt.args.statusCode)
			got := fmt.Sprint(err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStatusError_Unwrap(t *testing.T) {
	err := NewStatusError(io.ErrClosedPipe, http.StatusInternalServerError)
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestStatusError_Is(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "nil error",
			args: args{err: nil},
			want: false,
		},
		{
			name: "other error",
			args: args{err: io.EOF},
			want: false,
		},
		{
			name: "other parent",
			args: args{err: NewStatusError(io.EOF, http.StatusInternalServerError)},
			want: false,
		},
		{
			name: "other status",
			args: args{err: NewStatusError(io.ErrClosedPipe, http.StatusInsufficientStorage)},
			want: false,
		},
		{
			name: "same",
			args: args{err: NewStatusError(io.ErrClosedPipe, http.StatusInternalServerError)},
			want: true,
		},
		{
			name: "wrapped",
			args: args{err: fmt.Errorf("wrap: %w", NewStatusError(io.ErrClosedPipe, http.StatusInternalServerError))},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewStatusError(io.ErrClosedPipe, http.StatusInternalServerError)
			if got := e.Is(tt.args.err); got != tt.want {
				t.Errorf("StatusError.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
		wantLog    string
	}{
		{
			name:       "not a status or oidc error",
			err:        io.ErrClosedPipe,
			wantStatus: http.StatusInternalServerError,
			wantBody: `{
				"error":"server_error",
				"error_description":"io: read/write on closed pipe"
			}`,
			wantLog: `{
				"level":"ERROR",
				"msg":"request error",
				"oidc_error":{
					"description":"io: read/write on closed pipe",
					"parent":"io: read/write on closed pipe",
					"type":"server_error"
				},
				"status_code":500,
				"time":"not"
			}`,
		},
		{
			name:       "status error w/o oidc",
			err:        NewStatusError(io.ErrClosedPipe, http.StatusInternalServerError),
			wantStatus: http.StatusInternalServerError,
			wantBody: `{
				"error":"server_error",
				"error_description":"io: read/write on closed pipe"
			}`,
			wantLog: `{
				"level":"ERROR",
				"msg":"request error",
				"oidc_error":{
					"description":"io: read/write on closed pipe",
					"parent":"io: read/write on closed pipe",
					"type":"server_error"
				},
				"status_code":500,
				"time":"not"
			}`,
		},
		{
			name:       "oidc error w/o status",
			err:        oidc.ErrInvalidRequest().WithDescription("oops"),
			wantStatus: http.StatusBadRequest,
			wantBody: `{
				"error":"invalid_request",
				"error_description":"oops"
			}`,
			wantLog: `{
				"level":"WARN",
				"msg":"request error",
				"oidc_error":{
					"description":"oops",
					"type":"invalid_request"
				},
				"status_code":400,
				"time":"not"
			}`,
		},
		{
			name: "status with oidc error",
			err: NewStatusError(
				oidc.ErrUnauthorizedClient().WithDescription("oops"),
				http.StatusUnauthorized,
			),
			wantStatus: http.StatusUnauthorized,
			wantBody: `{
				"error":"unauthorized_client",
				"error_description":"oops"
			}`,
			wantLog: `{
				"level":"WARN",
				"msg":"request error",
				"oidc_error":{
					"description":"oops",
					"type":"unauthorized_client"
				},
				"status_code":401,
				"time":"not"
			}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOut := new(strings.Builder)
			logger := slog.New(
				slog.NewJSONHandler(logOut, &slog.HandlerOptions{
					Level: slog.LevelInfo,
				}).WithAttrs([]slog.Attr{slog.String("time", "not")}),
			)
			r := httptest.NewRequest("GET", "/target", nil)
			w := httptest.NewRecorder()

			WriteError(w, r, tt.err, logger)
			res := w.Result()
			assert.Equal(t, tt.wantStatus, res.StatusCode, "status code")
			gotBody, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			assert.JSONEq(t, tt.wantBody, string(gotBody), "body")
			assert.JSONEq(t, tt.wantLog, logOut.String())
		})
	}
}
