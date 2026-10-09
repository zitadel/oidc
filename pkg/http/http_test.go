package http

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

func TestHttpRequest_WrapsErrors(t *testing.T) {
	errRead := errors.New("connection reset")

	tests := []struct {
		name   string
		status int
		body   io.Reader
		check  func(t *testing.T, err error)
	}{
		{
			name:   "read body",
			status: http.StatusOK,
			body:   errReader{err: errRead},
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, errRead)
			},
		},
		{
			name:   "unmarshal",
			status: http.StatusOK,
			body:   strings.NewReader("not json"),
			check: func(t *testing.T, err error) {
				var syntaxErr *json.SyntaxError
				assert.ErrorAs(t, err, &syntaxErr)
			},
		},
		{
			name:   "oauth error response",
			status: http.StatusBadRequest,
			body:   strings.NewReader(`{"error":"invalid_grant","error_description":"code expired","state":"abc"}`),
			check: func(t *testing.T, err error) {
				var oidcErr *oidc.Error
				require.ErrorAs(t, err, &oidcErr)
				assert.Equal(t, oidc.InvalidGrant, oidcErr.ErrorType)
				assert.Equal(t, "code expired", oidcErr.Description)
				assert.Equal(t, "abc", oidcErr.State)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tt.status,
					Body:       io.NopCloser(tt.body),
					Request:    r,
				}, nil
			})}
			req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)

			var dst map[string]any
			err = HttpRequest(client, req, &dst)
			require.Error(t, err)
			tt.check(t, err)
		})
	}
}
