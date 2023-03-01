package op_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/pkg/op"
)

func TestCompileGlob(t *testing.T) {
	cases := []struct {
		glob        string
		uri         string
		expectError bool
		expectMatch bool
	}{
		{
			glob:        "http://example.com/foo/*",
			uri:         "http://example.com/foo/index.html",
			expectMatch: true,
		},
		{
			glob:        "http://example.com/foo/*",
			uri:         "http://example.com/index.html",
			expectMatch: false,
		},
		{
			glob:        "http://example.com/foo/[xl",
			expectError: true,
		},
	}
	for _, tc := range cases {
		t.Logf("glob: %s", tc.glob)
		compiled, err := op.CompileGlob(tc.glob)
		if tc.expectError {
			assert.Error(t, err, "compile")
			return
		}
		require.NoError(t, err, "compile")
		assert.Equal(t, tc.expectMatch, compiled.Match(tc.uri), tc.uri)
	}
}
