package test

import "net/http"

type RoundTripFunc func(req *http.Request) (*http.Response, error)

type roundTrip struct {
	fn RoundTripFunc
}

// NewRoundTripper creates a http.RoundTripper with the provided RoundTripFunc.
// RountTripFunc should validate the incoming request is what's expected
func NewRoundTripper(fn RoundTripFunc) http.RoundTripper {
	return &roundTrip{
		fn: fn,
	}
}

func (rt *roundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.fn(req)
	return resp, err
}
