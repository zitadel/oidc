package op

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNormalizeHTU covers the RFC 3986 syntax-based normalization applied to
// both the DPoP proof `htu` claim and the actual request URI before they are
// compared. Over-normalizing would let a proof minted for one endpoint be
// replayed against another, so the encoding-sensitive cases matter.
func TestNormalizeHTU(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "already normalized",
			raw:  "https://op.example.com/oauth/v2/token",
			want: "https://op.example.com/oauth/v2/token",
		},
		{
			name: "scheme and host lowercased",
			raw:  "HTTPS://OP.Example.COM/token",
			want: "https://op.example.com/token",
		},
		{
			name: "default https port removed",
			raw:  "https://op.example.com:443/token",
			want: "https://op.example.com/token",
		},
		{
			name: "default http port removed",
			raw:  "http://op.example.com:80/token",
			want: "http://op.example.com/token",
		},
		{
			name: "non-default port retained",
			raw:  "https://op.example.com:8443/token",
			want: "https://op.example.com:8443/token",
		},
		{
			name: "http on 443 is not a default port",
			raw:  "http://op.example.com:443/token",
			want: "http://op.example.com:443/token",
		},
		{
			name: "query and fragment removed",
			raw:  "https://op.example.com/token?foo=bar#frag",
			want: "https://op.example.com/token",
		},
		{
			name: "empty path becomes root",
			raw:  "https://op.example.com",
			want: "https://op.example.com/",
		},
		{
			name: "IPv6 host lowercased and bracketed",
			raw:  "https://[2001:DB8::1]/token",
			want: "https://[2001:db8::1]/token",
		},
		{
			name: "IPv6 host with non-default port",
			raw:  "https://[2001:DB8::1]:8443/token",
			want: "https://[2001:db8::1]:8443/token",
		},
		{
			// %2F is reserved: decoding it would merge distinct paths and
			// allow cross-endpoint proof replay.
			name: "encoded slash is preserved",
			raw:  "https://op.example.com/%2Ftoken",
			want: "https://op.example.com/%2Ftoken",
		},
		{
			name: "lowercase hex in reserved escape uppercased",
			raw:  "https://op.example.com/%2ftoken",
			want: "https://op.example.com/%2Ftoken",
		},
		{
			name: "unreserved escape decoded",
			raw:  "https://op.example.com/%7Euser",
			want: "https://op.example.com/~user",
		},
		{
			name: "lowercase unreserved escape decoded",
			raw:  "https://op.example.com/%7euser",
			want: "https://op.example.com/~user",
		},
		{
			name: "dot segments removed",
			raw:  "https://op.example.com/a/../../b",
			want: "https://op.example.com/b",
		},
		{
			// Empty segments are meaningful to some routers, so they must
			// survive normalization.
			name: "empty path segments preserved",
			raw:  "https://op.example.com//a//b",
			want: "https://op.example.com//a//b",
		},
		{name: "relative URI rejected", raw: "/token", wantErr: true},
		{name: "missing host rejected", raw: "https:///token", wantErr: true},
		{name: "non-http scheme rejected", raw: "ftp://op.example.com/token", wantErr: true},
		{name: "userinfo rejected", raw: "https://user@op.example.com/token", wantErr: true},
		{name: "userinfo with password rejected", raw: "https://user:pw@op.example.com/token", wantErr: true},
		{name: "truncated percent encoding rejected", raw: "https://op.example.com/token%", wantErr: true},
		{name: "invalid percent encoding rejected", raw: "https://op.example.com/token%zz", wantErr: true},
		{name: "unparseable URI rejected", raw: "https://op.example.com/token\x7f\x00", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHTU(tt.raw)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestNormalizeHTUIsIdempotent guards against a normalization step that keeps
// changing its own output, which would make comparison order-dependent.
func TestNormalizeHTUIsIdempotent(t *testing.T) {
	for _, raw := range []string{
		"HTTPS://OP.Example.COM:443/a/../b/%7euser?q=1#f",
		"http://op.example.com:80//a//b/%2Fc",
		"https://[2001:DB8::1]:8443/",
	} {
		once, err := normalizeHTU(raw)
		require.NoError(t, err)
		twice, err := normalizeHTU(once)
		require.NoError(t, err)
		assert.Equal(t, once, twice, "normalizeHTU(%q) is not idempotent", raw)
	}
}

func TestNormalizePercentEncoding(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "empty", value: "", want: ""},
		{name: "no escapes", value: "/oauth/v2/token", want: "/oauth/v2/token"},
		{name: "unreserved alpha decoded", value: "%41", want: "A"},
		{name: "unreserved digit decoded", value: "%30", want: "0"},
		{name: "unreserved tilde decoded", value: "%7E", want: "~"},
		{name: "unreserved hyphen decoded", value: "%2D", want: "-"},
		{name: "unreserved period decoded", value: "%2E", want: "."},
		{name: "unreserved underscore decoded", value: "%5F", want: "_"},
		{name: "lowercase hex unreserved decoded", value: "%7e", want: "~"},
		{name: "reserved slash kept uppercase", value: "%2F", want: "%2F"},
		{name: "reserved slash hex uppercased", value: "%2f", want: "%2F"},
		{name: "reserved space kept", value: "%20", want: "%20"},
		{name: "null byte kept", value: "%00", want: "%00"},
		{name: "multibyte utf8 kept per octet", value: "%c3%a9", want: "%C3%A9"},
		{name: "mixed literal and escapes", value: "/a%2Fb/%7ec", want: "/a%2Fb/~c"},
		{name: "trailing percent rejected", value: "abc%", wantErr: true},
		{name: "single hex digit rejected", value: "%4", wantErr: true},
		{name: "non hex digits rejected", value: "%zz", wantErr: true},
		{name: "second digit non hex rejected", value: "%4z", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizePercentEncoding(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsUnreserved(t *testing.T) {
	for _, value := range []byte{'a', 'z', 'A', 'Z', '0', '9', '-', '.', '_', '~'} {
		assert.True(t, isUnreserved(value), "expected %q to be unreserved", value)
	}
	for _, value := range []byte{'/', ':', '?', '#', '[', ']', '@', '!', '%', '+', ' ', 0x00, 0x7f, 0xc3} {
		assert.False(t, isUnreserved(value), "expected %q to be reserved", value)
	}
}

// TestRemoveDotSegments verifies RFC 3986 Section 5.2.4, including the
// deliberate deviation that empty path segments are not collapsed.
func TestRemoveDotSegments(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", "/"},
		{"/a/b/c", "/a/b/c"},
		{"/a/./b", "/a/b"},
		{"/./a", "/a"},
		{"/a/../b", "/b"},
		{"/a/b/../c", "/a/c"},
		{"/a/../../b", "/b"},
		{"/a/.", "/a/"},
		{"/a/..", "/"},
		{"/..", "/"},
		{"/../", "/"},
		{"/../a", "/a"},
		{".", ""},
		{"..", ""},
		{"./a", "a"},
		{"../a", "a"},
		// RFC 3986 Section 5.2.4 example.
		{"/a/b/c/./../../g", "/a/g"},
		// Empty segments are preserved rather than collapsed.
		{"//a//b", "//a//b"},
		{"/a//../b", "/a/b"},
		{"/a/b//", "/a/b//"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, removeDotSegments(tt.input))
		})
	}
}

func TestRemoveLastPathSegment(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"", ""},
		{"/", ""},
		{"/a", ""},
		{"/a/b", "/a"},
		{"/a/b/c", "/a/b"},
		{"a", ""},
		{"//a", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			assert.Equal(t, tt.want, removeLastPathSegment(tt.value))
		})
	}
}

func TestConstantTimeEqual(t *testing.T) {
	assert.True(t, constantTimeEqual("", ""))
	assert.True(t, constantTimeEqual("abc", "abc"))
	assert.False(t, constantTimeEqual("abc", "abd"))
	assert.False(t, constantTimeEqual("abc", "ab"))
	assert.False(t, constantTimeEqual("", "a"))
}
