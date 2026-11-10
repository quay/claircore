package common

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestUpdaterFetch(t *testing.T) {
	t.Parallel()
	connectionErr := errors.New("connection reset")
	table := []struct {
		name     string
		retries  int
		statuses []int
		body     string
		wantWait time.Duration
		wantErr  bool
	}{
		{
			name:     "OK",
			statuses: []int{http.StatusOK},
		},
		{
			name:     "NotModified",
			statuses: []int{http.StatusNotModified},
		},
		{
			name:     "NoRetries",
			statuses: []int{http.StatusServiceUnavailable},
			wantErr:  true,
		},
		{
			name:     "NoRetriesRequestError",
			statuses: []int{0},
			wantErr:  true,
		},
		{
			name:     "NegativeRetries",
			retries:  -1,
			statuses: []int{http.StatusServiceUnavailable},
			wantErr:  true,
		},
		{
			name:     "NotModifiedAfterRetry",
			retries:  2,
			statuses: []int{http.StatusServiceUnavailable, http.StatusNotModified},
			wantWait: 10 * time.Second,
		},
		{
			name:     "ServerError",
			retries:  2,
			statuses: []int{http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusOK},
			wantWait: 30 * time.Second,
		},
		{
			name:     "TooManyRequests",
			retries:  2,
			statuses: []int{http.StatusTooManyRequests, http.StatusOK},
			wantWait: 10 * time.Second,
		},
		{
			name:     "RequestError",
			retries:  2,
			statuses: []int{0, http.StatusOK},
			wantWait: 10 * time.Second,
		},
		{
			name:    "ServerErrorExhausted",
			retries: 2,
			statuses: []int{
				http.StatusServiceUnavailable,
				http.StatusServiceUnavailable,
				http.StatusServiceUnavailable,
			},
			wantWait: 30 * time.Second,
			wantErr:  true,
		},
		{
			name:     "RequestErrorExhausted",
			retries:  2,
			statuses: []int{0, 0, 0},
			wantWait: 30 * time.Second,
			wantErr:  true,
		},
		{
			name:    "BackoffLimit",
			retries: 5,
			statuses: []int{
				http.StatusServiceUnavailable,
				http.StatusServiceUnavailable,
				http.StatusServiceUnavailable,
				http.StatusServiceUnavailable,
				http.StatusServiceUnavailable,
				http.StatusOK,
			},
			wantWait: 190 * time.Second,
		},
		{
			name:     "NotFound",
			retries:  2,
			statuses: []int{http.StatusNotFound},
			wantErr:  true,
		},
		{
			name:     "NotImplemented",
			retries:  2,
			statuses: []int{http.StatusNotImplemented},
			wantErr:  true,
		},
		{
			name:     "InvalidJSON",
			retries:  2,
			statuses: []int{http.StatusOK},
			body:     "invalid JSON",
			wantErr:  true,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				type mapping struct {
					Value string `json:"value"`
				}
				const lastModified = "Mon, 02 Jan 2006 15:04:05 GMT"
				initial := &mapping{Value: "initial"}
				u := NewUpdater("https://example.com/mapping.json", initial)
				u.MaxRetries = tt.retries
				u.lastModified = lastModified
				var calls int
				bodies := []*mappingBody{}
				c := &http.Client{Transport: mappingTransport(func(req *http.Request) (*http.Response, error) {
					if calls >= len(tt.statuses) {
						t.Fatal("unexpected retry")
					}
					if got := req.Header.Get("If-Modified-Since"); got != lastModified {
						t.Errorf("If-Modified-Since = %q, want %q", got, lastModified)
					}
					for _, b := range bodies {
						if !b.closed {
							t.Error("response body still open before retry")
						}
					}
					status := tt.statuses[calls]
					calls++
					if status == 0 {
						return nil, connectionErr
					}
					body := tt.body
					if body == "" {
						body = `{"value":"updated"}`
					}
					b := &mappingBody{Reader: strings.NewReader(body)}
					bodies = append(bodies, b)
					return &http.Response{
						StatusCode: status,
						Header:     http.Header{"Last-Modified": {"Tue, 03 Jan 2006 15:04:05 GMT"}},
						Body:       b,
					}, nil
				})}
				start := time.Now()
				err := u.Fetch(t.Context(), c)
				if (err != nil) != tt.wantErr {
					t.Fatalf("Fetch error = %v, want error: %v", err, tt.wantErr)
				}
				lastStatus := tt.statuses[len(tt.statuses)-1]
				if lastStatus == 0 && !errors.Is(err, connectionErr) {
					t.Errorf("Fetch error = %v, want %v", err, connectionErr)
				}
				if calls != len(tt.statuses) {
					t.Errorf("requests = %d, want %d", calls, len(tt.statuses))
				}
				if got := time.Since(start); got != tt.wantWait {
					t.Errorf("elapsed time = %s, want %s", got, tt.wantWait)
				}
				for _, b := range bodies {
					if !b.closed {
						t.Error("response body still open after fetch")
					}
				}
				if tt.wantErr || lastStatus == http.StatusNotModified {
					if u.value.Load() != initial || u.lastModified != lastModified {
						t.Error("cached mapping changed without a successful download")
					}
					return
				}
				if got := u.value.Load().(*mapping).Value; got != "updated" {
					t.Errorf("mapping value = %q, want updated", got)
				}
				if u.lastModified != "Tue, 03 Jan 2006 15:04:05 GMT" {
					t.Errorf("Last-Modified not updated: %q", u.lastModified)
				}
			})
		})
	}
}

func TestUpdaterFetchCancellation(t *testing.T) {
	t.Parallel()
	for _, cancelAfter := range []time.Duration{0, 5 * time.Second, 15 * time.Second} {
		t.Run(cancelAfter.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), cancelAfter)
				defer cancel()
				u := NewUpdater("https://example.com/mapping.json", new(map[string]any))
				u.MaxRetries = 2
				var calls int
				c := &http.Client{Transport: mappingTransport(func(req *http.Request) (*http.Response, error) {
					if err := req.Context().Err(); err != nil {
						return nil, err
					}
					calls++
					return &http.Response{
						StatusCode: http.StatusServiceUnavailable,
						Body:       io.NopCloser(strings.NewReader("unavailable")),
					}, nil
				})}
				start := time.Now()
				if err := u.Fetch(ctx, c); !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("Fetch error = %v, want deadline exceeded", err)
				}
				if got := time.Since(start); got != cancelAfter {
					t.Errorf("elapsed time = %s, want %s", got, cancelAfter)
				}
				wantCalls := 0
				if cancelAfter > 0 {
					wantCalls = 1
				}
				if cancelAfter > 10*time.Second {
					wantCalls = 2
				}
				if calls != wantCalls {
					t.Errorf("requests = %d, want %d", calls, wantCalls)
				}
			})
		})
	}
}

type mappingTransport func(*http.Request) (*http.Response, error)

func (f mappingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type mappingBody struct {
	io.Reader
	closed bool
}

func (b *mappingBody) Close() error {
	b.closed = true
	return nil
}
