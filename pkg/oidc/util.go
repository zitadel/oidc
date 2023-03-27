package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// mergeAndMarshalClaims merges registered and the custom
// claims map into a single JSON object.
// Registered fields overwrite custom claims.
func mergeAndMarshalClaims(registered any, extraClaims map[string]any) ([]byte, error) {
	// Use a buffer for memory re-use, instead off letting
	// json allocate a new []byte for every step.
	buf := new(bytes.Buffer)

	// Marshal the registered claims into JSON
	if err := json.NewEncoder(buf).Encode(registered); err != nil {
		return nil, fmt.Errorf("oidc registered claims: %w", err)
	}

	if len(extraClaims) > 0 {
		merged := make(map[string]any)
		for k, v := range extraClaims {
			merged[k] = v
		}

		// Merge JSON data into custom claims.
		// The full-read action by the decoder resets the buffer
		// to zero len, while retaining underlaying cap.
		if err := json.NewDecoder(buf).Decode(&merged); err != nil {
			return nil, fmt.Errorf("oidc registered claims: %w", err)
		}

		// Marshal the final result.
		if err := json.NewEncoder(buf).Encode(merged); err != nil {
			return nil, fmt.Errorf("oidc custom claims: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// unmarshalJSONMulti unmarshals the same JSON data into multiple destinations.
// Each destination must be a pointer, as per json.Unmarshal rules.
// Returns on the first error and destinations may be partly filled with data.
func unmarshalJSONMulti(data []byte, destinations ...any) error {
	for _, dst := range destinations {
		if err := json.Unmarshal(data, dst); err != nil {
			return fmt.Errorf("oidc: %w into %T", err, dst)
		}
	}
	return nil
}
