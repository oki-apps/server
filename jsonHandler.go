package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

//JSONHandler represents methods that generate any JSON marshallable content fron an HTTP request
type JSONHandler func(r *http.Request) (interface{}, error)

func (h JSONHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	statusCode := http.StatusOK
	if r.Method == "POST" {
		statusCode = http.StatusAccepted
	}

	data, err := h(r)

	if err != nil {
		handleError(w, r, err)
		return
	}

	if data == nil {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(statusCode)
		encoder := json.NewEncoder(w)
		err := encoder.Encode(data)
		if err != nil {
			fmt.Println(err)
			handleError(w, r, err)
			return
		}
	}
}
