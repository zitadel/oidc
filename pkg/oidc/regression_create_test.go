//go:build create_regression_data

package oidc

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test_create_regression generates the regression data.
// It is excluded from regular testing, unless
// called with the create_regression_data tag:
// go test -tags="create_regression_data" ./pkg/oidc
func Test_create_regression(t *testing.T) {
	for _, obj := range regressionData {
		file, err := os.Create(jsonFilename(obj))
		require.NoError(t, err)
		defer file.Close()

		encodeJSON(t, file, obj)
	}
}
