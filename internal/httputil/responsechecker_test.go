package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var respBody = `Sorry this resource isn't available at the moment, please try again later when the resource might be available`

func TestLimitedReadResponse(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(respBody))
	}))
	defer svr.Close()

	cl := svr.Client()
	res, err := cl.Get(svr.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckResponse(res, http.StatusOK)
	if err == nil {
		t.Fatal("expected an error")
	}
	wantErrMsg := `unexpected status code: "404 Not Found" for "` + svr.URL + `" (body starts: "Sorry this resource isn't available at the moment, please try again later when the resource might be available")`
	if err.Error() != wantErrMsg {
		t.Errorf("expected different error message, got: %q, want %q", err.Error(), wantErrMsg)
	}
}
