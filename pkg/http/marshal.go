package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func MarshalJSON(w http.ResponseWriter, i interface{}) {
	MarshalJSONWithStatus(w, i, http.StatusOK)
}

func MarshalJSONWithStatus(w http.ResponseWriter, i interface{}, status int) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	if i == nil {
		return
	}
	err := json.NewEncoder(w).Encode(i)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func ConcatenateJSON(first, second []byte) ([]byte, error) {
	if !bytes.HasSuffix(first, []byte{'}'}) {
		return nil, fmt.Errorf("jws: invalid JSON %s", first)
	}
	if !bytes.HasPrefix(second, []byte{'{'}) {
		return nil, fmt.Errorf("jws: invalid JSON %s", second)
	}
	// check empty
	if len(first) == 2 {
		return second, nil
	}
	if len(second) == 2 {
		return first, nil
	}

	first[len(first)-1] = ','
	first = append(first, second[1:]...)
	return first, nil
}
