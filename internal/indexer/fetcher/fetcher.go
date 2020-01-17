package fetcher

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

// Fetcher is a private struct which implements indexer.Fetcher.
type fetcher struct {
	wc      *http.Client
	cleanMu sync.Mutex
	clean   []string
}

// New creates a new indexer.Fetcher which downloads layers to temporary files.
// If a nil *http.Client is provided, the default client will be used.
//
// Fetcher is safe to share concurrently.
//
// The provided LayerFetchOpt is currently ignored.
func New(client *http.Client, _ indexer.LayerFetchOpt) *fetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return &fetcher{
		wc: client,
	}
}

// Fetch retrieves a layer from the provided claircore.Layer.URI field,
// decompresses the archive if compressed, and copies the the http body
// either to an in memory layer.Bytes field or popultes layer.LocalPath with
// a local file system path to the archive.
func (f *fetcher) Fetch(ctx context.Context, layers []*claircore.Layer) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, l := range layers {
		ll := l
		g.Go(func() error {
			err := f.fetch(ctx, ll)
			return err
		})
	}
	// wait for any concurrent fetches to finish
	if err := g.Wait(); err != nil {
		return fmt.Errorf("encountered error while fetching a layer: %v", err)
	}
	return nil
}

func (f *fetcher) filename(l *claircore.Layer) string {
	// TODO(hank) Make this configurable directly, instead of only via TMPDIR.
	return filepath.Join(os.TempDir(), l.Hash)
}

// fetch is designed to be ran as a go routine. performs the logic for for
// fetching an individual layer's contents.
func (f *fetcher) fetch(ctx context.Context, layer *claircore.Layer) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/indexer/fetcher/fetcher.fetch").
		Str("layer", layer.Hash).
		Logger()
	log.Debug().Msg("layer fetch start")
	// It is valid and don't perform a fetch.
	if layer.Fetched() {
		log.Debug().Msg("layer fetch skipped: exists")
		return nil
	}

	// if no RemotePath was provided return error
	if layer.URI == "" {
		return fmt.Errorf("empty uri for layer %v", layer.Hash)
	}
	// parse uri
	url, err := url.ParseRequestURI(layer.URI)
	if err != nil {
		return fmt.Errorf("failied to parse remote path uri: %v", err)
	}
	if layer.Hash == "" {
		return fmt.Errorf("digest is empty")
	}
	// When the hash turns into real digest type, this needs to be variable.
	vh := sha256.New()
	want, err := hex.DecodeString(layer.Hash)
	if err != nil {
		return err
	}

	// Open our target file before hitting the network.
	name := f.filename(layer)
	if err := layer.SetLocal(name); err != nil {
		return err
	}
	fd, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrExist):
		log.Debug().Msg("layer fetch skipped: exists")
		// Another goroutine is grabbing this layer, return nothing.
		//
		// This is racy, but the caller should have prevented this instance of a
		// fetcher from trying to fetch the same layer multiple times.
		//
		// TODO Verify that layers are only assigned once across the whole
		// system.
		return nil
	default:
		return fmt.Errorf("fetcher: unable to create file: %w", err)
	}
	defer fd.Close()
	f.cleanup(fd.Name())

	req := &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Method:     http.MethodGet,
		URL:        url,
		Header:     layer.Headers,
	}
	req = req.WithContext(ctx)
	resp, err := f.wc.Do(req)
	if err != nil {
		return fmt.Errorf("fetcher: request failed: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	default:
		return fmt.Errorf("fetcher: unexpected status code: %d %s", resp.StatusCode, resp.Status)
	}
	tr := io.TeeReader(resp.Body, vh)

	br := bufio.NewReader(tr)
	// Look at the content-type and optionally fix it up.
	ct := resp.Header.Get("content-type")
	switch {
	case ct == "" ||
		ct == "text/plain" ||
		ct == "application/octet-stream":
		log.Debug().
			Str("content-type", ct).
			Msg("guessing compression")
		b, err := br.Peek(4)
		if err != nil {
			return err
		}
		switch detectCompression(b) {
		case cmpGzip:
			ct = "application/gzip"
		case cmpZstd:
			ct = "application/zstd"
		case cmpNone:
			ct = "application/x-tar"
		}
		log.Debug().
			Str("format", ct).
			Msg("guessed compression")
	}

	var r io.Reader
	switch {
	case ct == "application/gzip":
		fallthrough
	case strings.HasSuffix(ct, ".tar+gzip"):
		g, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer g.Close()
		r = g
	case ct == "application/zstd":
		fallthrough
	case strings.HasSuffix(ct, ".tar+zstd"):
		s, err := zstd.NewReader(br)
		if err != nil {
			return err
		}
		defer s.Close()
		r = s
	case ct == "application/x-tar":
		fallthrough
	case strings.HasSuffix(ct, ".tar"):
		r = br
	default:
		return fmt.Errorf("fetcher: unknown content-type %q", ct)
	}

	buf := bufio.NewWriter(fd)
	defer buf.Flush()
	n, err := io.Copy(buf, r)
	log.Debug().Int64("size", n).Msg("wrote file")
	if err != nil {
		return err
	}
	if got := vh.Sum(nil); !bytes.Equal(got, want) {
		err := fmt.Errorf("fetcher: validation failed: got %q, expected %q",
			hex.EncodeToString(got),
			hex.EncodeToString(want))
		return err
	}

	log.Debug().Msg("layer fetch ok")
	return nil
}

func (f *fetcher) Close() (err error) {
	// BUG(hank) The Close method only captures the last error.
	f.cleanMu.Lock()
	defer f.cleanMu.Unlock()
	for _, n := range f.clean {
		if e := os.Remove(n); e != nil {
			err = e
		}
	}
	return err
}

func (f *fetcher) cleanup(name string) {
	f.cleanMu.Lock()
	defer f.cleanMu.Unlock()
	f.clean = append(f.clean, name)
}
