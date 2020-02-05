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
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
)

const (
	ua = `claircore/test/fetch`
)

var registry = map[string]struct {
	Auth, Service, Registry string
}{
	"docker.io": {
		Auth:     "https://auth.docker.io/",
		Service:  "registry.docker.io",
		Registry: "https://registry-1.docker.io/",
	},
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

	urls, ok := registry[from]
	if !ok {
		return nil, errors.New("")
	}
	header := http.Header{
		"User-Agent": {ua},
	}
	if c == nil {
		c = http.DefaultClient
	}

	// Request a token
	u, err := url.Parse(urls.Auth)
	if err != nil {
		return nil, err
	}
	u, err = u.Parse("token")
	if err != nil {
		return nil, err
	}
	v := url.Values{
		"service": {urls.Service},
		"scope":   {fmt.Sprintf("repository:%s:pull", repo)},
	}
	u.RawQuery = v.Encode()
	req := &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL:        u,
		Host:       u.Host,
		Method:     http.MethodGet,
		Header:     header,
	}
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return nil, errors.New(res.Status)
	}
	defer res.Body.Close()
	var tok tokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil {
		return nil, err
	}
	header.Set("Authorization", "Bearer "+tok.Token)

	// grab
	u, err = url.Parse(urls.Registry)
	if err != nil {
		return nil, err
	}
	u, err = u.Parse(path.Join("v2", repo, "blobs", blob.String()))
	if err != nil {
		return nil, err
	}
	req = &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		URL:        u,
		Host:       u.Host,
		Method:     http.MethodGet,
		Header:     header,
	}
	res, err = c.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	switch res.StatusCode {
	case http.StatusOK:
	default:
		return nil, errors.New(res.Status)
	}
	defer res.Body.Close()

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
		gr, err = gzip.NewReader(res.Body)
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
