//go:build !create_regression_data

package oidc

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_assert_regression verifies current output from
// json.Marshal to stored regression data.
// These tests are only ran when the create_regression_data
// tag is NOT set.
func Test_assert_regression(t *testing.T) {
	buf := new(strings.Builder)

	for _, obj := range regressionData {
		name := jsonFilename(obj)
		t.Run(name, func(t *testing.T) {
			file, err := os.Open(name)
			require.NoError(t, err)
			defer file.Close()

			_, err = io.Copy(buf, file)
			require.NoError(t, err)
			want := buf.String()
			buf.Reset()

			encodeJSON(t, buf, obj)
			first := buf.String()
			buf.Reset()

			assert.JSONEq(t, want, first)

			require.NoError(t,
				json.Unmarshal([]byte(first), obj),
			)
			second, err := json.Marshal(obj)
			require.NoError(t, err)

			assert.JSONEq(t, want, string(second))
		})
	}
}
