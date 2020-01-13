package fastesturl_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/quay/claircore/pkg/fastesturl"
)

// TestFastestURLFailure confirms we return nil
// when all requests fail the default RespCheck
func TestFastestURLAllFailure(t *testing.T) {
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("X-Test-Server", "1")
		w.WriteHeader(http.StatusBadRequest)
		return
	}))
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("X-Test-Server", "2")
		w.WriteHeader(http.StatusBadRequest)
		return
	}))
	url1, _ := url.Parse(ts1.URL)
	url2, _ := url.Parse(ts2.URL)
	furl := fastesturl.New(nil, nil, nil, []*url.URL{url1, url2})
	resp := furl.Do(context.TODO())
	if resp != nil {
		t.Fatalf("resp should be nil")
	}
}

// TestFastestURLFailure confirms we only return an http.Response
// that passes the default RespCheck function despite it being
// the slower server
func TestFastestURLFailure(t *testing.T) {
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("X-Test-Server", "1")
		w.WriteHeader(http.StatusBadRequest)
		return
	}))
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("X-Test-Server", "2")
		return
	}))
	url1, _ := url.Parse(ts1.URL)
	url2, _ := url.Parse(ts2.URL)
	furl := fastesturl.New(nil, nil, nil, []*url.URL{url1, url2})
	resp := furl.Do(context.TODO())
	if resp == nil {
		t.Fatalf("resp should not be nil")
	}
	respServer := resp.Header.Get("X-Test-Server")
	if respServer != "2" {
		t.Fatalf("test server 1 should be first")
	}
}

// TestFastestURLSuccess confirms the fastest server wins
// when all servers respond successfully
func TestFastestURLSuccess(t *testing.T) {
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("X-Test-Server", "1")
		return
	}))
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("X-Test-Server", "2")
		return
	}))
	url1, _ := url.Parse(ts1.URL)
	url2, _ := url.Parse(ts2.URL)
	furl := fastesturl.New(nil, nil, nil, []*url.URL{url1, url2})
	resp := furl.Do(context.TODO())
	if resp == nil {
		t.Fatalf("resp should not be nil")
	}
	respServer := resp.Header.Get("X-Test-Server")
	if respServer != "1" {
		t.Fatalf("test server 1 should be first")
	}
}
