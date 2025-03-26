// Package fetch implements just enough of a client for the OCI Distribution
// specification for use in tests.
package fetch

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/claircore/test/internal/cache"
)

const (
	ua = `claircore/test/fetch`
)

var registry = map[string]*client{
	"docker.io":                  {Root: "https://registry-1.docker.io/"},
	"gcr.io":                     {Root: "https://gcr.io/"},
	"ghcr.io":                    {Root: "https://ghcr.io/"},
	"quay.io":                    {Root: "https://quay.io/"},
	"registry.access.redhat.com": {Root: "https://registry.access.redhat.com/"},
}

var pkgClient = &http.Client{
	Transport: &http.Transport{},
}

// Layer returns the specified layer contents, cached in the global layer cache.
func Layer(ctx context.Context, t testing.TB, from, repo string, blob claircore.Digest, opt ...Option) (*os.File, error) {
	t.Helper()
	opts := make(map[Option]bool)
	for _, o := range opt {
		opts[o] = true
	}
	// Splitting the digest like this future-proofs things against some weirdo
	// running this on Windows.
	cachefile := filepath.Join(integration.CacheDir(t), cache.Layer, blob.Algorithm(), hex.EncodeToString(blob.Checksum()))
	switch _, err := os.Stat(cachefile); {
	case err == nil:
		t.Logf("layer cached: %s", cachefile)
		return os.Open(cachefile)
	case errors.Is(err, os.ErrNotExist) && opts[IgnoreIntegration]:
	case errors.Is(err, os.ErrNotExist):
		// need to do work
		integration.Skip(t)
	default:
		return nil, err
	}
	checkpath.Do(func() {
		if err := os.MkdirAll(filepath.Dir(cachefile), 0o755); err != nil {
			t.Errorf("unable to create needed directories: %v", err)
		}
	})
	t.Logf("fetching layer into: %s", cachefile)

	client, ok := registry[from]
	if !ok {
		return nil, fmt.Errorf("unknown registry: %q", from)
	}
	blobReader, err := client.Blob(ctx, pkgClient, repo, blob)
	if err != nil {
		return nil, err
	}
	defer blobReader.Close()
	ck := blob.Hash()
	rd := io.TeeReader(blobReader, ck)
	// BUG(hank) Any compression scheme that isn't gzip isn't handled correctly.
	if !opts[NoDecompression] {
		var gr *gzip.Reader
		gr, err = gzip.NewReader(rd)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		rd = gr
	}
	cf := copyTo(t, cachefile, rd)
	if got, want := ck.Sum(nil), blob.Checksum(); !bytes.Equal(got, want) {
		t.Errorf("bad digest: got: %x, want: %x", got, want)
	}
	if t.Failed() {
		os.Remove(cachefile)
		return nil, errors.New("unable to open cachefile")
	}
	return cf, nil
}

// Option is options for [Fetch]
type Option uint

const (
	_ Option = iota
	// IgnoreIntegration causes [Fetch] to use the network unconditionally.
	IgnoreIntegration
	// NoDecompression does no compression.
	NoDecompression
)

// Checkpath guards against making the same directory over and over.
var checkpath sync.Once

func copyTo(t testing.TB, name string, rc io.Reader) *os.File {
	cf, err := os.Create(name)
	if err != nil {
		t.Error(err)
		return nil
	}
	t.Cleanup(func() {
		if err := cf.Close(); err != nil {
			t.Log(err)
		}
	})

	if _, err = io.Copy(cf, rc); err != nil {
		t.Error(err)
		return nil
	}
	if err = cf.Sync(); err != nil {
		t.Error(err)
		return nil
	}
	if _, err = cf.Seek(0, io.SeekStart); err != nil {
		t.Error(err)
		return nil
	}

	return cf
}

type tokenResponse struct {
	Token string `json:"token"`
}

// Client is a more generic registry client.
type client struct {
	tokCache sync.Map
	Root     string
}

func (d *client) getToken(repo string) string {
	if v, ok := d.tokCache.Load(repo); ok {
		return v.(string)
	}
	return ""
}

func (d *client) putToken(repo, tok string) {
	d.tokCache.Store(repo, tok)
}

func (d *client) doAuth(ctx context.Context, c *http.Client, name, h string) error {
	if !strings.HasPrefix(h, `Bearer `) {
		return errors.New("weird header")
	}
	attrs := map[string]string{}
	fs := strings.Split(strings.TrimPrefix(h, `Bearer `), ",")
	for _, f := range fs {
		i := strings.IndexByte(f, '=')
		if i == -1 {
			return errors.New("even weirder header")
		}
		k := f[:i]
		v := strings.Trim(f[i+1:], `"`)
		attrs[k] = v
	}

	// Request a token
	u, err := url.Parse(attrs["realm"])
	if err != nil {
		return err
	}
	v := url.Values{
		"service": {attrs["service"]},
		"scope":   {attrs["scope"]},
	}
	u.RawQuery = v.Encode()
	req := &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Proto:      "HTTP/1.1",
		URL:        u,
		Host:       u.Host,
		Method:     http.MethodGet,
		Header:     http.Header{"User-Agent": {ua}},
	}
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return fmt.Errorf("%s %v: %v", req.Method, req.URL, res.Status)
	}
	defer res.Body.Close()
	var tok tokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil {
		return err
	}
	d.putToken(name, "Bearer "+tok.Token)
	return nil
}

func (d *client) Blob(ctx context.Context, c *http.Client, name string, blob claircore.Digest) (io.ReadCloser, error) {
	u, err := url.Parse(d.Root)
	if err != nil {
		return nil, err
	}
	u, err = u.Parse(path.Join("v2", name, "blobs", blob.String()))
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL:        u,
		Host:       u.Host,
		Method:     http.MethodGet,
		Header:     http.Header{"User-Agent": {ua}},
	}
	if h := d.getToken(name); h != "" {
		req.Header.Set(`authorization`, h)
	}
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		auth := res.Header.Get(`www-authenticate`)
		if err := d.doAuth(ctx, c, name, auth); err != nil {
			return nil, err
		}
		return d.Blob(ctx, c, name, blob)
	default:
		return nil, fmt.Errorf("%s %v: %v", req.Method, req.URL, res.Status)
	}
	return res.Body, nil
}
