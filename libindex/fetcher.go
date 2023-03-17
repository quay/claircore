package libindex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	_ "unsafe" // Needed for linker tricks.

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/toolkit/spool"
)

// Arena does coordination and global refcounting.
type Arena interface {
	Realizer(context.Context) indexer.Realizer
	Close(context.Context) error
}

var (
	_ Arena            = (*RemoteFetchArena)(nil)
	_ indexer.Realizer = (*FetchProxy)(nil)
)

// RemoteFetchArena is a struct that keeps track of all the layers fetched into it,
// and only removes them once all the users have gone away.
//
// Exported for use in cctool. If cctool goes away, this can get unexported. It is
// remote in the sense that it pulls layers from the internet.
type RemoteFetchArena struct {
	wc *http.Client
	sf *singleflight.Group

	mu sync.Mutex
	// Rc is a map of digest to refcount.
	rc    map[string]int
	files map[string]*spool.File

	root *spool.Arena
}

// NewRemoteFetchArena initializes the RemoteFetchArena.
//
// This method is provided instead of a constructor function to make embedding
// easier.
func NewRemoteFetchArena(ctx context.Context, wc *http.Client, root string) (*RemoteFetchArena, error) {
	a, err := spool.NewArena(ctx, root, `fetcher`)
	if err != nil {
		return nil, err
	}
	return &RemoteFetchArena{
		wc:    wc,
		root:  a,
		sf:    &singleflight.Group{},
		rc:    make(map[string]int),
		files: make(map[string]*spool.File),
	}, nil
}

func (a *RemoteFetchArena) forget(digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	ct, ok := a.rc[digest]
	if !ok {
		return nil
	}
	ct--
	if ct == 0 {
		f := a.files[digest]
		delete(a.rc, digest)
		delete(a.files, digest)
		return f.Close()
	}
	a.rc[digest] = ct
	return nil
}

// FetchOne does a deduplicated fetch, then increments the refcount and renames
// the file to the permanent place if applicable.
func (a *RemoteFetchArena) fetchOne(ctx context.Context, l *claircore.Layer) (do func() error) {
	do = func() error {
		h := l.Hash.String()
		var sf *spool.File
		select {
		case res := <-a.sf.DoChan(h, func() (interface{}, error) {
			return a.realizeLayer(ctx, l)
		}):
			if err := res.Err; err != nil {
				return fmt.Errorf("error realizing layer %s: %w", h, err)
			}
			sf = res.Val.(*spool.File)
		case <-ctx.Done():
			return ctx.Err()
		}
		a.mu.Lock()
		a.rc[h] += 1
		a.mu.Unlock()
		setLayerFile(l, sf)
		return nil
	}
	return do
}

//go:linkname setLayerFile github.com/quay/claircore.setLayerFile
func setLayerFile(l *claircore.Layer, f *spool.File) error

// Close removes all files left in the arena.
//
// It's not an error to have active fetchers, but may cause errors to have files
// unlinked underneath their users.
func (a *RemoteFetchArena) Close(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/fetchArena.Close")
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.rc) != 0 {
		zlog.Warn(ctx).
			Int("count", len(a.rc)).
			Msg("seem to have active fetchers")
		zlog.Info(ctx).
			Msg("clearing arena")
	}
	for d := range a.rc {
		delete(a.rc, d)
		a.sf.Forget(d)
	}
	if err := a.root.Close(); err != nil {
		return err
	}
	return nil
}

// RealizeLayer is the inner function used inside the singleflight.
//
// The returned value is a temporary filename in the arena.
func (a *RemoteFetchArena) realizeLayer(ctx context.Context, l *claircore.Layer) (*spool.File, error) {
	digest := l.Hash.String()
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/fetchArena.realizeLayer",
		"layer", digest,
		"uri", l.URI)
	zlog.Debug(ctx).Msg("layer fetch start")

	// Validate the layer input.
	if l.URI == "" {
		return nil, fmt.Errorf("empty uri for layer %v", l.Hash)
	}
	url, err := url.ParseRequestURI(l.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote path uri: %v", err)
	}
	if l.Hash.Checksum() == nil {
		return nil, fmt.Errorf("digest is empty")
	}
	vh := l.Hash.Hash()
	want := l.Hash.Checksum()

	// Do we already have a copy? This can happen if there are strictly
	// sequential calls.
	var prev *spool.File
	a.mu.Lock()
	prev = a.files[digest]
	a.mu.Unlock()
	if prev != nil {
		return prev, nil
	}

	// Open our target file before hitting the network.
	fail := true
	fd, err := a.root.NewFile(ctx, `layer.`)
	if err != nil {
		return nil, fmt.Errorf("fetcher: unable to create file: %w", err)
	}
	name := fd.Name()
	ctx = zlog.ContextWithValues(ctx, "path", name)
	defer func() {
		if fail {
			if err := fd.Close(); err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to close layer file")
			}
		}
	}()
	// It'd be nice to be able to pre-allocate our file on disk, but we can't
	// because of decompression.

	req := &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Method:     http.MethodGet,
		URL:        url,
		Header:     l.Headers,
	}
	req = req.WithContext(ctx)
	resp, err := a.wc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetcher: request failed: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	default:
		// Especially for 4xx errors, the response body may indicate what's going
		// on, so include some of it in the error message. Capped at 256 bytes in
		// order to not flood the log.
		bodyStart, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		if err == nil {
			return nil, fmt.Errorf("fetcher: unexpected status code: %s (body starts: %q)",
				resp.Status, bodyStart)
		}
		return nil, fmt.Errorf("fetcher: unexpected status code: %s", resp.Status)
	}
	tr := io.TeeReader(resp.Body, vh)

	br := bufio.NewReader(tr)
	// Look at the content-type and optionally fix it up.
	ct := resp.Header.Get("content-type")
	zlog.Debug(ctx).
		Str("content-type", ct).
		Msg("reported content-type")
	if ct == "" || ct == "text/plain" || ct == "binary/octet-stream" || ct == "application/octet-stream" {
		zlog.Debug(ctx).
			Str("content-type", ct).
			Msg("guessing compression")
		b, err := br.Peek(4)
		if err != nil {
			return nil, err
		}
		switch detectCompression(b) {
		case cmpGzip:
			ct = "application/gzip"
		case cmpZstd:
			ct = "application/zstd"
		case cmpNone:
			ct = "application/x-tar"
		}
		zlog.Debug(ctx).
			Str("format", ct).
			Msg("guessed compression")
	}

	var r io.Reader
	switch {
	case ct == "application/vnd.docker.image.rootfs.diff.tar.gzip":
		// Catch the old docker media type.
		fallthrough
	case ct == "application/gzip" || ct == "application/x-gzip":
		// GHCR reports gzipped layers as the latter.
		fallthrough
	case strings.HasSuffix(ct, ".tar+gzip"):
		g, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer g.Close()
		r = g
	case ct == "application/zstd":
		fallthrough
	case strings.HasSuffix(ct, ".tar+zstd"):
		s, err := zstd.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer s.Close()
		r = s
	case ct == "application/x-tar":
		fallthrough
	case strings.HasSuffix(ct, ".tar"):
		r = br
	default:
		return nil, fmt.Errorf("fetcher: unknown content-type %q", ct)
	}

	buf := bufio.NewWriter(fd)
	n, err := io.Copy(buf, r)
	zlog.Debug(ctx).Int64("size", n).Msg("wrote file")
	if err != nil {
		return nil, err
	}
	if err := buf.Flush(); err != nil {
		return nil, err
	}
	if got := vh.Sum(nil); !bytes.Equal(got, want) {
		err := fmt.Errorf("fetcher: validation failed: got %q, expected %q",
			hex.EncodeToString(got),
			hex.EncodeToString(want))
		return nil, err
	}

	zlog.Debug(ctx).
		Msg("checking if layer is a valid tar")
	// TODO(hank) Need media types somewhere in here.
	switch _, err := tarfs.New(fd); {
	case errors.Is(err, nil):
	case errors.Is(err, tarfs.ErrFormat):
		fallthrough
	default:
		return nil, err
	}

	zlog.Debug(ctx).Msg("layer fetch ok")
	fail = false
	a.mu.Lock()
	a.files[digest] = fd
	a.mu.Unlock()
	return fd, nil
}

// Fetcher returns an indexer.Fetcher.
func (a *RemoteFetchArena) Realizer(_ context.Context) indexer.Realizer {
	return &FetchProxy{a: a}
}

// FetchProxy tracks the files fetched for layers.
//
// This can be unexported if FetchArena gets unexported.
type FetchProxy struct {
	a     *RemoteFetchArena
	clean []string
}

// Realize populates all the layers locally.
func (p *FetchProxy) Realize(ctx context.Context, ls []*claircore.Layer) error {
	g, ctx := errgroup.WithContext(ctx)
	p.clean = make([]string, len(ls))
	for i, l := range ls {
		p.clean[i] = l.Hash.String()
		g.Go(p.a.fetchOne(ctx, l))
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("encountered error while fetching a layer: %w", err)
	}
	return nil
}

// Close marks all the layers' backing files as unused.
//
// This method may actually delete the backing files.
func (p *FetchProxy) Close() error {
	var err error
	for _, digest := range p.clean {
		e := p.a.forget(digest)
		if e != nil {
			if err == nil {
				err = e
			} else {
				err = fmt.Errorf("%v; %v", err, e)
			}
		}
	}
	if err != nil {
		return err
	}
	return nil
}

type compression int

const (
	cmpGzip compression = iota
	cmpZstd
	cmpNone
)

var cmpHeaders = [...][]byte{
	{0x1F, 0x8B, 0x08},       // cmpGzip
	{0x28, 0xB5, 0x2F, 0xFD}, // cmpZstd
}

func detectCompression(b []byte) compression {
	for c, h := range cmpHeaders {
		if len(b) < len(h) {
			continue
		}
		if bytes.Equal(h, b[:len(h)]) {
			return compression(c)
		}
	}
	return cmpNone
}
