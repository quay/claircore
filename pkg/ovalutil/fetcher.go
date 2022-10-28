package ovalutil

import (
	"compress/bzip2"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

// Compressor is used by Fetcher to decompress data it fetches.
type Compressor uint

//go:generate stringer -type Compressor -linecomment

// These are the kinds of Compession a Fetcher can deal with.
const (
	CompressionAuto  Compressor = iota // auto
	CompressionNone                    // none
	CompressionGzip                    // gzip
	CompressionBzip2                   // bzip2
	CompressionZstd                    // zstd
)

// ParseCompressor reports the Compressor indicated by the passed in string.
func ParseCompressor(s string) (c Compressor, err error) {
	switch s {
	case "gz", "gzip":
		c = CompressionGzip
	case "bz2", "bzip2":
		c = CompressionBzip2
	case "zstd":
		c = CompressionZstd
	case "none":
		c = CompressionNone
	case "", "auto":
		c = CompressionAuto
	default:
		return c, fmt.Errorf("ovalutil: unknown compression scheme %q", s)
	}
	return c, nil
}

// Fetcher implements the driver.Fetcher interface.
//
// Fetcher expects all of its exported members to be filled out appropriately,
// and may panic if not.
type Fetcher struct {
	URL         *url.URL
	Client      *http.Client
	Compression Compressor
}

// Configure implements driver.Configurable.
//
// For users that embed a Fetcher, this provides a configuration hook by
// default.
func (f *Fetcher) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "pkg/ovalutil/Fetcher.Configure")
	var cfg FetcherConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		uri, err := url.Parse(cfg.URL)
		if err != nil {
			return err
		}
		f.URL = uri
		zlog.Info(ctx).
			Msg("configured database URL")
	}
	if cfg.Compression != "" {
		c, err := ParseCompressor(cfg.Compression)
		if err != nil {
			return err
		}
		f.Compression = c
		zlog.Info(ctx).
			Msg("configured database compression")
	}

	f.Client = c
	return nil
}

// FetcherConfig is the configuration that the Fetcher's Configure method works
// with.
//
// Users the embed Fetcher and use Fetcher.Configure should make sure any of
// their configuration keys don't conflict with these names.
type FetcherConfig struct {
	URL         string `json:"url" yaml:"url"`
	Compression string `json:"compression" yaml:"compression"`
}

// Fetch fetches the resource as specified by Fetcher.URL and
// Fetcher.Compression, using the client provided as Fetcher.Client.
//
// Fetch makes GET requests, and will make conditional requests using the
// passed-in hint.
//
// Tmp.File is used to return a ReadCloser that outlives the passed-in context.
func (f *Fetcher) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "pkg/ovalutil/Fetcher.Fetch")
	zlog.Info(ctx).Str("database", f.URL.String()).Msg("starting fetch")
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
	var fp fingerprint
	if h := string(hint); h != "" {
		if err := json.Unmarshal([]byte(h), &fp); err == nil {
			fp.Set(req.Header)
		}
	}

	res, err := f.Client.Do(req.WithContext(ctx))
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, hint, err
	}
	switch res.StatusCode {
	case http.StatusOK:
		if fp.Etag == "" || fp.Etag != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil, hint, driver.Unchanged
	default:
		return nil, hint, fmt.Errorf("ovalutil: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}
	zlog.Debug(ctx).Msg("request ok")

	var r io.Reader
	cmp := f.Compression
Compression:
	switch cmp {
	case CompressionAuto:
		var kind string
		for _, h := range []string{`content-type`, `content-disposition`} {
			v := res.Header.Get(h)
			if v == "" {
				continue
			}
			switch h {
			case `content-type`:
				kind, _, err = mime.ParseMediaType(v)
				if err == nil {
					goto Found
				}
			case `content-disposition`:
				var params map[string]string
				_, params, err = mime.ParseMediaType(v)
				if err != nil {
					break
				}
				fn, ok := params["filename"]
				if !ok {
					break
				}
				kind = mime.TypeByExtension(path.Ext(fn))
				if kind != "" {
					goto Found
				}
			default:
				panic("programmer error")
			}
			zlog.Debug(ctx).
				Err(err).
				Str("header", h).
				Str("value", v).
				Msg("failed to parse incoming HTTP header")
		}
		kind = mime.TypeByExtension(path.Ext(res.Request.URL.Path))
	Found:
		switch kind {
		case `application/x-bzip2`:
			cmp = CompressionBzip2
		case `application/gzip`, `application/x-gzip`:
			cmp = CompressionGzip
		case `application/zstd`:
			cmp = CompressionZstd
		default:
			// unknown type
			cmp = CompressionNone
		}
		goto Compression
	case CompressionNone:
		r = res.Body
	case CompressionGzip:
		gz, err := getGzip(res.Body)
		if err != nil {
			return nil, hint, err
		}
		defer putGzip(gz)
		r = gz
	case CompressionBzip2:
		r = bzip2.NewReader(res.Body)
	case CompressionZstd:
		zz, err := getZstd(res.Body)
		if err != nil {
			return nil, hint, err
		}
		defer putZstd(zz)
		r = zz
	default:
		panic(fmt.Sprintf("ovalutil: programmer error: unknown compression scheme: %v", f.Compression))
	}
	zlog.Debug(ctx).
		Stringer("compression", cmp).
		Msg("found compression scheme")

	tf, err := tmp.NewFile("", "fetcher.")
	if err != nil {
		return nil, hint, err
	}
	zlog.Debug(ctx).
		Str("path", tf.Name()).
		Msg("using tempfile")
	success := false
	defer func() {
		if !success {
			zlog.Debug(ctx).Msg("unsuccessful, cleaning up tempfile")
			if err := tf.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("failed to close tempfile")
			}
		}
	}()

	if _, err := io.Copy(tf, r); err != nil {
		return nil, hint, err
	}
	if o, err := tf.Seek(0, io.SeekStart); err != nil || o != 0 {
		return nil, hint, err
	}
	zlog.Debug(ctx).Msg("decompressed and buffered database")

	fp.From(res.Header)
	hint = fp.Fingerprint()
	success = true
	return tf, hint, nil
}

type fingerprint struct {
	Etag string `json:",omitempty"`
	Date string `json:",omitempty"`
}

func (f fingerprint) Set(h http.Header) {
	if f.Etag != "" {
		h.Set("if-none-match", f.Etag)
	}
	if f.Date != "" {
		h.Set("if-modified-since", f.Date)
	}
}

func (f *fingerprint) From(h http.Header) {
	if tag := h.Get("etag"); tag != "" {
		f.Etag = tag
	}
	f.Date = h.Get("last-modified")
}

func (f fingerprint) Fingerprint() driver.Fingerprint {
	b, _ := json.Marshal(f)
	return driver.Fingerprint(string(b))
}
