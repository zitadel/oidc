package oidc

// This file contains common functions and data for regression testing

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const dataDir = "regression_data"

// jsonFilename builds a filename for the regression testdata.
// dataDir/<type_name>.json
func jsonFilename(obj any) string {
	name := fmt.Sprintf("%T.json", obj)
	return path.Join(
		dataDir,
		strings.TrimPrefix(name, "*"),
	)
}

func encodeJSON(t *testing.T, w io.Writer, obj any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	require.NoError(t, enc.Encode(obj))
}

var regressionData = []any{
	accessTokenData,
	idTokenData,
	introspectionResponseData,
	userInfoData,
	jwtProfileAssertionData,
}
