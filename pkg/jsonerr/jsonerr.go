package jsonerr

import (
	"encoding/json"
	"net/http"
)

type Additional interface{}

type Response struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Additional must be json serializable or expect errors
	Additional `json:"additional,omitempty"`
}

// JsonError works like http.Error but uses our response
// struct as the body of the response. Like http.Error
// you will still need to call a naked return in the http handler
func Error(w http.ResponseWriter, r *Response, httpcode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(httpcode)
	b, _ := json.Marshal(r)

	w.Write(b)
}
