package utils

import (
	"encoding/json"
	"net/http"

	"github.com/caos/utils/logging"
)

func MarshalJSON(w http.ResponseWriter, i interface{}) {
	b, err := json.Marshal(i)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = w.Write(b)
	logging.Log("UTILS-zVu9OW").OnError(err).Error("error writing response")
}
