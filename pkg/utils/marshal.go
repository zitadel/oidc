package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

func MarshalJSON(w http.ResponseWriter, i interface{}) {
	b, err := json.Marshal(i)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, err = w.Write(b)
	if err != nil {
		logrus.Error("error writing response")
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
