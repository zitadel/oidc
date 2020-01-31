package utils

import (
	"encoding/json"
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
