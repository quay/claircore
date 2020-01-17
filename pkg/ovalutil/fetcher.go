package ovalutil

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

// Compressor is used by Fetcher to decompress data it fetches.
type Compressor uint

//go:generate stringer -type Compressor -linecomment

// These are the kinds of Compession a Fetcher can deal with.
const (
	CompressionNone  Compressor = iota // none
	CompressionGzip                    // gzip
	CompressionBzip2                   // bzip2
)

// ParseCompressor reports the Compressor indicated by the passed in string.
func ParseCompressor(s string) (c Compressor, err error) {
	switch s {
	case "gz", "gzip":
		c = CompressionGzip
	case "bz2", "bzip2":
		c = CompressionBzip2
	case "", "none":
		c = CompressionNone
	default:
		return c, fmt.Errorf("ovalutil: unknown compression scheme %q", s)
	}
	return c, nil
}

// Fetcher implements the driver.FetcherNG interface.
//
// Fetcher expects all of its exported members to be filled out appropriately,
// and may panic if not.
type Fetcher struct {
	Compression Compressor
	URL         *url.URL
	Client      *http.Client
}

// Fetch fetches the resource as specified by Fetcher.URL and
// Fetcher.Compression, using the client provided as Fetcher.Client.
//
// Fetch makes GET requests, and will make conditional requests using the
// passed-in hint as an HTTP date. The returned hint will be an HTTP date if the
// server sends a Last-Modified header.
//
// Tmp.File is used to return a ReadCloser that outlives the passed-in context.
func (f *Fetcher) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "pkg/ovalutil/Fetcher.Fetch").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Str("database", f.URL.String()).Msg("starting fetch")
	req := http.Request{
		Method: http.MethodGet,
		Header: http.Header{
			"User-Agent": {"claircore/pkg/ovalutil.Fetcher"},
		},
		URL:        f.URL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       f.URL.Host,
	}
	if hint != "" {
		log.Debug().
			Str("hint", string(hint)).
			Msg("using hint")
		req.Header.Set("If-Modified-Since", string(hint))
	}

	res, err := f.Client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, hint, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		return nil, hint, driver.Unchanged
	case http.StatusOK:
		// break
	default:
		return nil, hint, fmt.Errorf("ovalutil: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}
	log.Debug().Msg("request ok")

	var r io.Reader
	switch f.Compression {
	case CompressionNone:
		r = res.Body
	case CompressionGzip:
		r, err = gzip.NewReader(res.Body)
	case CompressionBzip2:
		r = bzip2.NewReader(res.Body)
	default:
		panic(fmt.Sprintf("ovalutil: programmer error: unknown compression scheme: %v", f.Compression))
	}
	log.Debug().
		Str("compression", f.Compression.String()).
		Msg("found compression scheme")

	tf, err := tmp.NewFile("", "fetcher.")
	if err != nil {
		return nil, hint, err
	}
	log.Debug().
		Str("path", tf.Name()).
		Msg("using tempfile")
	success := false
	defer func() {
		if !success {
			log.Debug().Msg("unsuccessful, cleaing up tempfile")
			if err := tf.Close(); err != nil {
				log.Warn().Err(err).Msg("failed to close tempfile")
			}
		}
	}()

	if _, err := io.Copy(tf, r); err != nil {
		return nil, hint, err
	}
	if o, err := tf.Seek(0, io.SeekStart); err != nil || o != 0 {
		return nil, hint, err
	}
	log.Debug().Msg("decompressed and buffered database")

	if t := res.Header.Get("Last-Modified"); t != "" {
		hint = driver.Fingerprint(t)
	}
	log.Debug().
		Str("hint", string(hint)).
		Msg("using new hint")
	success = true
	return tf, hint, nil
}
