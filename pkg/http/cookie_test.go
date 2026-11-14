package http

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/securecookie"
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

func newRequest() *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://rp.example.com/callback", nil)
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

func TestCookieHandler_CheckQueryCookie(t *testing.T) {
	t.Run("CheckQueryCookie: cookie equals query parameter", func(t *testing.T) {
		handler := NewCookieHandler(testCookieKey, testCookieKey)

		r := newRequest()
		r.URL.RawQuery = url.Values{testCookieName: {testCookieValue}}.Encode()
		r.AddCookie(setTestCookie(t, handler, testCookieName, testCookieValue))

		got, err := handler.CheckQueryCookie(r, testCookieName)
		require.NoError(t, err)
		assert.Equal(t, testCookieValue, got)
	})
}

func TestCookieHandler_CheckQueryCookie_Errors(t *testing.T) {
	tests := []struct {
		name        string
		query       url.Values
		withCookie  bool
		expectedErr string
	}{
		{
			name:        "cookie differs from query parameter",
			query:       url.Values{testCookieName: {"other"}},
			withCookie:  true,
			expectedErr: testCookieName + " does not compare",
		},
		{
			name:        "no query parameter",
			withCookie:  true,
			expectedErr: testCookieName + " does not compare",
		},
		{
			name:        "no cookie",
			query:       url.Values{testCookieName: {testCookieValue}},
			expectedErr: http.ErrNoCookie.Error(),
		},
	}
	for _, test := range tests {
		t.Run("CheckQueryCookie error reason: "+test.name, func(t *testing.T) {
			handler := NewCookieHandler(testCookieKey, testCookieKey)

			r := newRequest()
			r.URL.RawQuery = test.query.Encode()
			if test.withCookie {
				r.AddCookie(setTestCookie(t, handler, testCookieName, testCookieValue))
			}

			got, err := handler.CheckQueryCookie(r, testCookieName)

			require.EqualError(t, err, test.expectedErr)
			assert.Empty(t, got)
		})
	}
}

func TestCookieHandler_RequestAware(t *testing.T) {
	t.Run("IsRequestAware", func(t *testing.T) {
		normalCookieHandler := NewCookieHandler(testCookieKey, testCookieKey)
		assert.False(t, normalCookieHandler.IsRequestAware())

		reqAwareCookieHandler := NewRequestAwareCookieHandler(func(*http.Request) (*securecookie.SecureCookie, error) {
			return securecookie.New(testCookieKey, testCookieKey), nil
		})
		assert.True(t, reqAwareCookieHandler.IsRequestAware())
	})
}

func TestCookieHandler_SetCookie(t *testing.T) {
	t.Run("SetCookie on a request aware handler", func(t *testing.T) {
		c := NewRequestAwareCookieHandler(func(*http.Request) (*securecookie.SecureCookie, error) {
			return securecookie.New(testCookieKey, testCookieKey), nil
		})

		w := httptest.NewRecorder()
		err := c.SetCookie(w, testCookieName, testCookieValue)
		require.EqualError(t, err, "cookie handler is request aware")
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("SetRequestAwareCookie on a normal cookie handler", func(t *testing.T) {
		c := NewCookieHandler(testCookieKey, testCookieKey)

		w := httptest.NewRecorder()
		r := newRequest()
		err := c.SetRequestAwareCookie(r, w, testCookieName, testCookieValue)
		require.EqualError(t, err, "cookie handler is not request aware")
		assert.Empty(t, w.Result().Cookies())
	})
}
