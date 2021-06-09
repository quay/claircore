package fetch

import (
	"compress/gzip"
	"context"
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
)

const (
	ua = `claircore/test/fetch`
)

var registry = map[string]*client{
	"docker.io": &client{Root: "https://registry-1.docker.io/"},
	"quay.io":   &client{Root: "https://quay.io/"},
	"gcr.io":    &client{Root: "https://gcr.io/"},
}

func Layer(ctx context.Context, t *testing.T, c *http.Client, from, repo string, blob claircore.Digest) (*os.File, error) {
	cachefile := filepath.Join("testdata", blob.String()+".layer")
	switch _, err := os.Stat(cachefile); {
	case err == nil:
		return os.Open(cachefile)
	case errors.Is(err, os.ErrNotExist):
		// need to do work
		integration.Skip(t)
	default:
		return nil, err
	}

	if c == nil {
		c = http.DefaultClient
	}
	client, ok := registry[from]
	if !ok {
		return nil, fmt.Errorf("unknown registry: %q", from)
	}
	rc, err := client.Blob(ctx, c, repo, blob)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	err = func() error {
		var err error
		defer func() {
			if err != nil {
				os.Remove(cachefile)
			}
		}()

		var cf *os.File
		cf, err = os.Create(cachefile)
		if err != nil {
			return err
		}
		defer cf.Close()

		var gr *gzip.Reader
		gr, err = gzip.NewReader(rc)
		if err != nil {
			return err
		}
		defer gr.Close()

		if _, err = io.Copy(cf, gr); err != nil {
			return err
		}
		if err = cf.Sync(); err != nil {
			return err
		}

		return nil
	}()

	if err != nil {
		return nil, err
	}

	return os.Open(cachefile)
}

type tokenResponse struct {
	Token string `json:"token"`
}

// Client is a more generic registry client.
type client struct {
	Root     string
	tokCache sync.Map
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
	u, err = u.Parse("token")
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
