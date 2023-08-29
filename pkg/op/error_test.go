package op

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/schema"
	"golang.org/x/exp/slog"
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
