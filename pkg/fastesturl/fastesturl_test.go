package fastesturl_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/quay/claircore/pkg/fastesturl"
)

// Server sets up two testing servers, returning the two status codes in order.
//
// The returned RespCheck function must be used to ensure that both servers
// return responses.
func server(t *testing.T, a, b int) (*url.URL, *url.URL, fastesturl.RespCheck, func()) {
	// TODO Use t.Cleanup instead of returning a function when our minimum go
	// version is 1.14.
	var closeSem sync.Once
	sem := make(chan struct{})
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Server", "1")
		w.WriteHeader(a)
		return
	}))
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-sem
		w.Header().Set("X-Test-Server", "2")
		w.WriteHeader(b)
		return
	}))
	urla, err := url.Parse(srv1.URL)
	if err != nil {
		t.Error(err)
	}
	urlb, err := url.Parse(srv2.URL)
	if err != nil {
		t.Error(err)
	}
	return urla, urlb,
		func(resp *http.Response) bool {
			defer closeSem.Do(func() { close(sem) })
			return resp.StatusCode == http.StatusOK
		},
		func() {
			srv1.CloseClientConnections()
			srv1.Close()
			srv2.CloseClientConnections()
			srv2.Close()
		}
}

// TestFastestURLFailure confirms we return nil
// when all requests fail the default RespCheck
func TestFastestURLAllFailure(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	a, b, check, cleanup := server(t, http.StatusBadRequest, http.StatusBadRequest)
	defer cleanup()

	furl := fastesturl.New(nil, nil, check, []*url.URL{a, b})
	resp := furl.Do(ctx)
	if resp != nil {
		t.Fatalf("resp should be nil")
	}
}

// TestFastestURLFailure confirms we only return an http.Response
// that passes the default RespCheck function despite it being
// the slower server
func TestFastestURLFailure(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	a, b, check, cleanup := server(t, http.StatusBadRequest, http.StatusOK)
	defer cleanup()

	furl := fastesturl.New(nil, nil, check, []*url.URL{a, b})
	resp := furl.Do(ctx)
	if resp == nil {
		t.Fatalf("resp should not be nil")
	}
	respServer := resp.Header.Get("X-Test-Server")
	if respServer != "2" {
		t.Fatalf("test server 2 should be returned")
	}
}

// NOTE(hank) There used to be a test here "confirming" that the first request
// was the one actually returned when multiple success happen. It was removed
// because of flakiness in CI and we decided that it wasn't actually important
// that the absolute first response be returned despite scheduler and OS jitter.

func TestSuccess(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	a, b, check, cleanup := server(t, http.StatusOK, http.StatusOK)
	defer cleanup()

	furl := fastesturl.New(nil, nil, check, []*url.URL{a, b})
	resp := furl.Do(ctx)
	if resp == nil {
		t.Fatal("resp should be not nil")
	}
}
