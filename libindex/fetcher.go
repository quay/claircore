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
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/quay/claircore/indexer"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/tarfs"
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
	wc  *http.Client
	sem *semaphore.Weighted
	sf  singleflight.Group

	root  string
	mu    sync.Mutex
	cache map[string]*refct
}

// NewRemoteFetchArena initializes the RemoteFetchArena.
//
// Close must be called to release disk space, or the program may panic.
func NewRemoteFetchArena(wc *http.Client, root string) *RemoteFetchArena {
	a := &RemoteFetchArena{
		wc:    wc,
		root:  root,
		cache: make(map[string]*refct),
		sem:   semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0))),
	}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(a, func(a *RemoteFetchArena) {
		panic(fmt.Sprintf("%s:%d: fetcher arena not closed", file, line))
	})

	return a
}

// Refct is a refcounter for the os.File.
//
// The first [RemoteFetchArena.forget] call that has the "ct" member drop to zero also closes
// the File.
type refct struct {
	*os.File
	ct uint64
}

var errNotExist = errors.New("asked to forget nonexistent digest")

func (a *RemoteFetchArena) forget(digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rc, ok := a.cache[digest]
	if !ok {
		return errNotExist
	}
	rc.ct--
	if rc.ct != 0 {
		return nil
	}
	delete(a.cache, digest)
	var f *os.File
	f, rc.File = rc.File, nil
	return f.Close()
}

// FetchOne ...
func (a *RemoteFetchArena) fetchOne(ctx context.Context, l *claircore.Layer) (*os.File, error) {
	h := l.Hash.String()
Again:
	select {
	case res := <-a.sf.DoChan(h, func() (interface{}, error) {
		// This weird construction ensures that the slow part is not done
		// under the big lock.
		a.mu.Lock()
		if _, ok := a.cache[h]; !ok {
			a.mu.Unlock()
			rc, err := a.realizeLayer(ctx, l)
			if err != nil {
				return nil, err
			}
			a.mu.Lock()
			a.cache[h] = rc
		}
		a.mu.Unlock()

		return nil, nil
	}):
		if err := res.Err; err != nil {
			return nil, err
		}
		a.mu.Lock()
		rc, ok := a.cache[h]
		if !ok {
			// Getting to this arm means two Proxies had their calls interleaved such
			// that one had its Close method called and completed between the time
			// another one called DoChan and then obtained the lock.
			//
			// This is relatively common in tests where very little work is done after a
			// Layer is fetched, but should be rare in actual use.
			//
			// One way to fix this would be to implement a graveyard and then only really
			// delete the file once the graveyard is full.
			a.mu.Unlock()
			goto Again
		}
		fd := int(rc.Fd())
		if fd < 0 {
			panic(fmt.Sprintf("somehow got stale *os.File for %q", h))
		}
		f, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err != nil {
			a.mu.Unlock()
			return nil, err
		}
		rc.ct++
		a.mu.Unlock()
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close releases any held resources and reports what was still open via the error.
func (a *RemoteFetchArena) Close(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/fetchArena.Close",
		"arena", a.root)
	var leak []string
	a.mu.Lock()
	defer a.mu.Unlock()
	runtime.SetFinalizer(a, nil)
	for h, rc := range a.cache {
		rc.Close()
		delete(a.cache, h)
		leak = append(leak, h)
	}
	if len(leak) != 0 {
		return leakErr(leak)
	}
	return nil
}

func leakErr(h []string) error {
	sort.Strings(h)
	var b strings.Builder
	b.WriteString("fetcher: outstanding layers collected at close:\n")
	for _, h := range h {
		b.WriteByte('\t')
		b.WriteString(h)
		b.WriteByte('\n')
	}
	return errors.New(b.String())
}

// RealizeLayer fetches the layer. Meant to be called from inside the singleflight.
func (a *RemoteFetchArena) realizeLayer(ctx context.Context, l *claircore.Layer) (*refct, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/RemoteFetchArena.realizeLayer",
		"arena", a.root,
		"layer", l.Hash.String(),
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
	// Have to do real work, so grab a semaphore.
	if err := a.sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer a.sem.Release(1)

	// Open our target file before hitting the network.
	fd, err := os.CreateTemp(a.root, "fetch.*")
	if err != nil {
		return nil, fmt.Errorf("fetcher: unable to create file: %w", err)
	}
	if err := os.Remove(fd.Name()); err != nil {
		return nil, fmt.Errorf("fetcher: unable to remove file: %w", err)
	}
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
	return &refct{File: fd}, nil
}

// Fetcher returns an indexer.Fetcher.
func (a *RemoteFetchArena) Realizer(_ context.Context) indexer.Realizer {
	p := &FetchProxy{a: a}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(p, func(p *FetchProxy) {
		panic(fmt.Sprintf("%s:%d: fetcher proxy not closed", file, line))
	})
	return p
}

// FetchProxy tracks the files fetched for layers.
//
// This can be unexported if FetchArena gets unexported.
type FetchProxy struct {
	a     *RemoteFetchArena
	clean []string
}

// Realize populates all the layers locally.
func (p *FetchProxy) Realize(ctx context.Context, ls []*claircore.Layer) ([]claircore.ReadAtCloser, error) {
	g, ctx := errgroup.WithContext(ctx)
	p.clean = make([]string, len(ls))
	fs := make([]claircore.ReadAtCloser, len(ls))
	one := func(i int) func() error {
		return func() (err error) {
			p.clean[i] = ls[i].Hash.String()
			fs[i], err = p.a.fetchOne(ctx, ls[i])
			if err != nil {
				return fmt.Errorf("%v: %w", ls[i].Hash.String(), err)
			}
			return nil
		}
	}
	for i := range ls {
		g.Go(one(i))
	}
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("encountered error while fetching layers: %w", err)
	}
	return fs, nil
}

// Close marks all the layers' backing files as unused.
//
// This method may actually delete the backing files.
func (p *FetchProxy) Close() error {
	runtime.SetFinalizer(p, nil)
	var err error
	for _, digest := range p.clean {
		e := p.a.forget(digest)
		if e != nil {
			e := fmt.Errorf("forget %q: %w", digest, e)
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
