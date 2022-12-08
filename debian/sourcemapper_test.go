package debian

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/quay/zlog"
)

type TestClientFunc func(req *http.Request) *http.Response

func (f TestClientFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func NewTestClient() (*http.Client, error) {
	f, err := os.Open("testdata/Bullseye-Sources.gz")
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	f.Close()

	return &http.Client{
		Transport: TestClientFunc(
			func(req *http.Request) *http.Response {
				w := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(b)),
				}
				w.Header.Set("Content-Type", "application/gzip")
				return w
			},
		),
	}, nil
}

func TestCreateSourcesMap(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	client, err := NewTestClient()
	if err != nil {
		t.Fatalf("got the error %v", err)
	}
	u, err := url.Parse("http://[::1]/")
	if err != nil {
		t.Fatal(err)
	}
	mapper := newSourcesMap(u, client)

	err = mapper.Update(ctx)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	opensshBinaries := mapper.Get("aalib")
	if len(opensshBinaries) != 3 {
		t.Fatalf("expected 3 binaries related to aalib found %d found %v", len(opensshBinaries), opensshBinaries)
	}

	tarBinaries := mapper.Get("389-ds-base")
	if len(tarBinaries) != 6 {
		t.Fatalf("expected 6 binaries related to 389-ds-base found %d found %v", len(tarBinaries), tarBinaries)
	}
}
