package httpreader

import (
	"context"
	"net/http"
)

// Option is used to set options in [New].
type Option func(context.Context, *Reader) error

// WithSize sets the size of the HTTP resource and skips rangefinding.
func WithSize(sz int64) Option {
	return func(_ context.Context, r *Reader) error {
		r.size = sz
		return nil
	}
}

// WithHeaders sets additional headers for requests.
func WithHeaders(h http.Header) Option {
	return func(_ context.Context, r *Reader) error {
		r.headers = h
		return nil
	}
}
