package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// these values must be % 16 == 0 else error from crypto/aes
const (
	testCookieName  = "testCookieName123"
	testCookieValue = "testCookieValue123"
)

var testCookieKey = []byte("testCookieKey123")

func setTestCookie(t *testing.T, c *CookieHandler, name, value string) *http.Cookie {
	t.Helper()

	w := httptest.NewRecorder()
	require.NoError(t, c.SetCookie(w, name, value))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

func Test_NewCookieHandler(t *testing.T) {
	tests := []struct {
		name     string
		opts     []CookieHandlerOpt
		expected http.Cookie
	}{
		{
			name: "defaults",
			expected: http.Cookie{
				Path:     "/",
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			},
		},
		{
			name: "WithUnsecure",
			opts: []CookieHandlerOpt{WithUnsecure()},
			expected: http.Cookie{
				Path:     "/",
				SameSite: http.SameSiteLaxMode,
			},
		},
		{
			name: "WithSameSite",
			opts: []CookieHandlerOpt{WithSameSite(http.SameSiteStrictMode)},
			expected: http.Cookie{
				Path:     "/",
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			},
		},
		{
			name: "WithMaxAge",
			opts: []CookieHandlerOpt{WithMaxAge(60)},
			expected: http.Cookie{
				Path:     "/",
				MaxAge:   60,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			},
		},
		{
			name: "WithDomain",
			opts: []CookieHandlerOpt{WithDomain("example.com")},
			expected: http.Cookie{
				Domain:   "example.com",
				Path:     "/",
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			},
		},
		{
			name: "WithPath",
			opts: []CookieHandlerOpt{WithPath("/auth")},
			expected: http.Cookie{
				Path:     "/auth",
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			},
		},
		{
			name: "all options",
			opts: []CookieHandlerOpt{
				WithUnsecure(),
				WithSameSite(http.SameSiteStrictMode),
				WithMaxAge(60),
				WithDomain("example.com"),
				WithPath("/auth"),
			},
			expected: http.Cookie{
				Domain:   "example.com",
				Path:     "/auth",
				MaxAge:   60,
				SameSite: http.SameSiteStrictMode,
			},
		},
	}
	for _, test := range tests {
		t.Run("NewCookieHandler: "+test.name, func(t *testing.T) {
			cookie := NewCookieHandler(testCookieKey, testCookieKey, test.opts...)
			assert.False(t, cookie.IsRequestAware())

			setCookie := setTestCookie(t, cookie, testCookieName, testCookieValue)
			assert.Equal(t, testCookieName, setCookie.Name)
			assert.NotEmpty(t, setCookie.Value)
			assert.NotEqual(t, testCookieValue, setCookie.Value, "value must not be stored in plain text")
			assert.Equal(t, test.expected.Domain, setCookie.Domain)
			assert.Equal(t, test.expected.Path, setCookie.Path)
			assert.Equal(t, test.expected.MaxAge, setCookie.MaxAge)
			assert.Equal(t, test.expected.Secure, setCookie.Secure)
			assert.Equal(t, test.expected.SameSite, setCookie.SameSite)
			assert.True(t, setCookie.HttpOnly)
		})
	}
}
