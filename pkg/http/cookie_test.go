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

var (
	testCookieKey      = []byte("testCookieKey123")
	testOtherCookieKey = []byte("123testCookieKey")
)

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

func TestCookieHandler_Attributes(t *testing.T) {
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
			handler := NewCookieHandler(testCookieKey, testCookieKey, test.opts...)

			cookie := setTestCookie(t, handler, testCookieName, testCookieValue)
			assert.Equal(t, testCookieName, cookie.Name)
			assert.NotEmpty(t, cookie.Value)
			assert.NotEqual(t, testCookieValue, cookie.Value, "value must not be stored in plain text")
			assert.Equal(t, test.expected.Domain, cookie.Domain)
			assert.Equal(t, test.expected.Path, cookie.Path)
			assert.Equal(t, test.expected.MaxAge, cookie.MaxAge)
			assert.Equal(t, test.expected.Secure, cookie.Secure)
			assert.Equal(t, test.expected.SameSite, cookie.SameSite)
			assert.True(t, cookie.HttpOnly)

			// we delete cookie in the same test for convenience and code reuse
			w := httptest.NewRecorder()
			handler.DeleteCookie(w, testCookieName)
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1)
			deleted := cookies[0]
			assert.Equal(t, testCookieName, deleted.Name)
			assert.Empty(t, deleted.Value)
			assert.Equal(t, -1, deleted.MaxAge)
			assert.Equal(t, test.expected.Domain, deleted.Domain)
			assert.Equal(t, test.expected.Path, deleted.Path)
			assert.Equal(t, test.expected.Secure, deleted.Secure)
			assert.Equal(t, test.expected.SameSite, deleted.SameSite)
			assert.True(t, deleted.HttpOnly)
		})
	}
}

func TestCookieHandler_CheckCookie(t *testing.T) {
	t.Run("CheckCookie: valid cookie", func(t *testing.T) {
		handler := NewCookieHandler(testCookieKey, testCookieKey)

		r := newRequest()
		r.AddCookie(setTestCookie(t, handler, testCookieName, testCookieValue))

		got, err := handler.CheckCookie(r, testCookieName)
		require.NoError(t, err)
		assert.Equal(t, testCookieValue, got)
	})
}

func TestCookieHandler_CheckCookie_Errors(t *testing.T) {
	tests := []struct {
		name        string
		cookie      func(t *testing.T, valid *http.Cookie) *http.Cookie
		expectedErr error
	}{
		{
			name: "no cookie",
			cookie: func(*testing.T, *http.Cookie) *http.Cookie {
				return nil
			},
			expectedErr: http.ErrNoCookie,
		},
		{
			name: "signed with another key",
			cookie: func(t *testing.T, _ *http.Cookie) *http.Cookie {
				other := NewCookieHandler(testOtherCookieKey, testOtherCookieKey)
				cookie, err := other.CreateCookie(testCookieName, testCookieValue)
				require.NoError(t, err)
				return cookie
			},
			expectedErr: securecookie.ErrMacInvalid,
		},
		{
			name: "value of a cookie with another name",
			cookie: func(t *testing.T, _ *http.Cookie) *http.Cookie {
				other := NewCookieHandler(testCookieKey, testCookieKey)
				cookie, err := other.CreateCookie("other", testCookieValue)
				require.NoError(t, err)
				cookie.Name = testCookieName
				return cookie
			},
			expectedErr: securecookie.ErrMacInvalid,
		},
		{
			name: "plain text value",
			cookie: func(*testing.T, *http.Cookie) *http.Cookie {
				return &http.Cookie{Name: testCookieName, Value: testCookieValue}
			},
		},
	}
	for _, test := range tests {
		t.Run("CheckCookie error reason: "+test.name, func(t *testing.T) {
			handler := NewCookieHandler(testCookieKey, testCookieKey)
			validCookie := setTestCookie(t, handler, testCookieName, testCookieValue)

			r := newRequest()
			if cookie := test.cookie(t, validCookie); cookie != nil {
				r.AddCookie(cookie)
			}

			got, err := handler.CheckCookie(r, testCookieName)
			require.Error(t, err)
			if test.expectedErr != nil {
				assert.ErrorIs(t, err, test.expectedErr)
			}
			assert.Empty(t, got)
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
