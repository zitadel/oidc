package mw_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/http/mw"
)

func Test_Chain_Use(t *testing.T) {
	mw := mw.New()

	var (
		expected = "abbcdbaa"
		got      string
	)

	mw.Use(
		func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got += "a"

				h.ServeHTTP(w, r)

				got += "aa"
			})
		},
		func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got += "bb"

				h.ServeHTTP(w, r)

				got += "b"
			})
		},
		func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got += "c"

				h.ServeHTTP(w, r)

				got += "d"
			})
		},
	)

	mw.Handle(http.MethodGet+" /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	mw.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "http://www.example.com/", nil),
	)

	if got != expected {
		t.Errorf("Chain executed middlewares in wrong order: got=%q expected=%q", got, expected)
	}
}
