package op

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIssuerInterceptor(t *testing.T) {
	type fields struct {
		issuerFromRequest IssuerFromRequest
	}
	type res struct {
		issuer string
	}
	tests := []struct {
		name   string
		fields fields
		res    res
	}{
		{
			"empty",
			fields{
				func(r *http.Request) string {
					return ""
				},
			},
			res{
				issuer: "",
			},
		},
		{
			"static",
			fields{
				func(r *http.Request) string {
					return "static"
				},
			},
			res{
				issuer: "static",
			},
		},
		{
			"host",
			fields{
				func(r *http.Request) string {
					return r.Host
				},
			},
			res{
				issuer: "issuer.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := NewIssuerInterceptor(tt.fields.issuerFromRequest)
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.res.issuer, IssuerFromContext(r.Context()))
			})
			req := httptest.NewRequest("", "https://issuer.com", nil)
			i.Handler(next).ServeHTTP(nil, req)
			i.HandlerFunc(next).ServeHTTP(nil, req)
		})
	}
}
