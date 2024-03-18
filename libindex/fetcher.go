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
	"strings"
	"sync"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/wart"
	"github.com/quay/claircore/internal/zreader"
)

var (
	_ indexer.FetchArena          = (*RemoteFetchArena)(nil)
	_ indexer.Realizer            = (*FetchProxy)(nil)
	_ indexer.DescriptionRealizer = (*FetchProxy)(nil)
)

// RemoteFetchArena uses disk space to track fetched layers, removing them once
// all users are done with the layers.
type RemoteFetchArena struct {
	wc *http.Client
	sf *singleflight.Group

	// Rc holds (string, *rc).
	//
	// The string is a layer digest.
	rc   sync.Map
	root string
}

// NewRemoteFetchArena returns an initialized RemoteFetchArena.
func NewRemoteFetchArena(wc *http.Client, root string) *RemoteFetchArena {
	return &RemoteFetchArena{
		wc:   wc,
		sf:   &singleflight.Group{},
		root: root,
	}
}

// Rc is a reference counter.
type rc struct {
	sync.Mutex
	val   *tempFile
	count int
	done  func()
}

// NewRc makes an rc.
func newRc(v *tempFile, done func()) *rc {
	return &rc{
		val:  v,
		done: done,
	}
}

// Dec decrements the reference count, closing the inner file and calling the
// cleanup hook if necessary.
func (r *rc) dec() (err error) {
	r.Lock()
	defer r.Unlock()
	if r.count == 0 {
		return errors.New("close botch: count already 0")
	}
	r.count--
	if r.count == 0 {
		r.done()
		err = r.val.Close()
	}
	return err
}

// Ref increments the reference count.
func (r *rc) Ref() *ref {
	r.Lock()
	r.count++
	r.Unlock()
	n := &ref{rc: r}
	runtime.SetFinalizer(n, (*ref).Close)
	return n
}

// Ref is a reference handle, RAII-style.
type ref struct {
	once sync.Once
	rc   *rc
}

// Val clones the inner File.
func (r *ref) Val() (*os.File, error) {
	r.rc.Lock()
	defer r.rc.Unlock()
	return r.rc.val.Reopen()
}

// Close decrements the refcount.
func (r *ref) Close() (err error) {
	did := false
	r.once.Do(func() {
		err = r.rc.dec()
		did = true
	})
	if !did {
		return errClosed
	}
	return err
}

// Errors out of the rc/ref types.
var (
	errClosed = errors.New("Ref already Closed")
	errStale  = errors.New("stale file reference")
)

// FetchInto populates "l" and "cl" via a [singleflight.Group].
//
// It returns a closure to be used with an [errgroup.Group]
func (a *RemoteFetchArena) fetchInto(ctx context.Context, l *claircore.Layer, cl *io.Closer, desc *claircore.LayerDescription) (do func() error) {
	key := desc.Digest
	// All the refcounting needs to happen _outside_ the singleflight, because
	// the result of a singleflight call can be shared. Without doing it this
	// way, the refcount would be incorrect.
	do = func() error {
		ctx, span := tracer.Start(ctx, "RemoteFetchArena.fetchInto", trace.WithAttributes(attribute.String("key", key)))
		defer span.End()
		var c *rc
		var err error
		defer func() {
			span.RecordError(err)
			if err == nil {
				span.SetStatus(codes.Ok, "")
			} else {
				span.SetStatus(codes.Error, "fetchInto error")
			}
			return
		}()

		try := func() (any, error) {
			return a.fetchUnlinkedFile(ctx, key, desc)
		}
		select {
		case res := <-a.sf.DoChan(key, try):
			if e := res.Err; e != nil {
				err = fmt.Errorf("error realizing layer %s: %w", key, e)
				return err
			}
			c = res.Val.(*rc)
			span.AddEvent("got value from singleflight")
			span.SetAttributes(attribute.Bool("shared", res.Shared))
		case <-ctx.Done():
			err = context.Cause(ctx)
			return err
		}

		r := c.Ref()
		f, err := r.Val()
		switch {
		case errors.Is(err, nil):
		case errors.Is(err, errStale):
			zlog.Debug(ctx).Str("key", key).Msg("managed to get stale ref, retrying")
			return do()
		default:
			r.Close()
			return err
		}
		if err := l.Init(ctx, desc, f); err != nil {
			return errors.Join(err, f.Close(), r.Close())
		}
		*cl = closeFunc(func() error {
			return errors.Join(l.Close(), f.Close(), r.Close())
		})
		return nil
	}
	return do
}

// CloseFunc is an adapter in the vein of [http.HandlerFunc].
type closeFunc func() error

// Close implements [io.Closer].
func (f closeFunc) Close() error {
	return f()
}

// FetchUnlinkedFile is the inner function used inside the singleflight.
//
// Because we know we're the only concurrent call that's dealing with this key,
// we can be a bit more lax.
func (a *RemoteFetchArena) fetchUnlinkedFile(ctx context.Context, key string, desc *claircore.LayerDescription) (*rc, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/fetchArena.fetchUnlinkedFile",
		"arena", a.root,
		"layer", desc.Digest,
		"uri", desc.URI)
	ctx, span := tracer.Start(ctx, "RemoteFetchArena.fetchUnlinkedFile")
	defer span.End()
	span.SetStatus(codes.Error, "")
	zlog.Debug(ctx).Msg("layer fetch start")

	// Validate the layer input.
	if desc.URI == "" {
		return nil, fmt.Errorf("empty uri for layer %v", desc.Digest)
	}
	digest, err := claircore.ParseDigest(desc.Digest)
	if err != nil {
		return nil, err
	}
	url, err := url.ParseRequestURI(desc.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote path uri: %v", err)
	}
	v, ok := a.rc.Load(key)
	if ok {
		span.SetStatus(codes.Ok, "")
		return v.(*rc), nil
	}
	// Otherwise, it needs to be populated.
	f, err := openTemp(a.root)
	if err != nil {
		return nil, err
	}
	vh, want := digest.Hash(), digest.Checksum()

	// It'd be nice to be able to pre-allocate our file on disk, but we can't
	// because of decompression.

	req := (&http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Proto:      "HTTP/1.1",
		Host:       url.Host,
		Method:     http.MethodGet,
		URL:        url,
		Header:     http.Header(desc.Headers).Clone(),
	}).WithContext(ctx)
	resp, err := a.wc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetcher: request failed: %w", err)
	}
	defer resp.Body.Close()
	span.SetAttributes(attribute.Int("http.code", resp.StatusCode))
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

	// TODO(hank) All this decompression code could go away, but that would mean
	// that a buffer file would have to be allocated later, adding additional
	// disk usage.
	//
	// The ultimate solution is to move to a fetcher that proxies to HTTP range
	// requests.
	zr, kind, err := zreader.Detect(tr)
	if err != nil {
		return nil, fmt.Errorf("fetcher: error determining compression: %w", err)
	}
	defer zr.Close()
	// Look at the content-type and optionally fix it up.
	ct := resp.Header.Get("content-type")
	zlog.Debug(ctx).
		Str("content-type", ct).
		Msg("reported content-type")
	span.SetAttributes(attribute.String("payload.content-type", ct), attribute.Stringer("payload.compression.detected", kind))
	if ct == "" || ct == "text/plain" || ct == "binary/octet-stream" || ct == "application/octet-stream" {
		switch kind {
		case zreader.KindGzip:
			ct = "application/gzip"
		case zreader.KindZstd:
			ct = "application/zstd"
		case zreader.KindNone:
			ct = "application/x-tar"
		default:
			return nil, fmt.Errorf("fetcher: disallowed compression kind: %q", kind.String())
		}
		zlog.Debug(ctx).
			Str("content-type", ct).
			Msg("fixed content-type")
		span.SetAttributes(attribute.String("payload.content-type.detected", ct))
	}

	var wantZ zreader.Compression
	switch {
	case ct == "application/vnd.docker.image.rootfs.diff.tar.gzip":
		// Catch the old docker media type.
		fallthrough
	case ct == "application/gzip" || ct == "application/x-gzip":
		// GHCR reports gzipped layers as the latter.
		fallthrough
	case strings.HasSuffix(ct, ".tar+gzip"):
		wantZ = zreader.KindGzip
	case ct == "application/zstd":
		fallthrough
	case strings.HasSuffix(ct, ".tar+zstd"):
		wantZ = zreader.KindZstd
	case ct == "application/x-tar":
		fallthrough
	case strings.HasSuffix(ct, ".tar"):
		wantZ = zreader.KindNone
	default:
		return nil, fmt.Errorf("fetcher: unknown content-type %q", ct)
	}
	if kind != wantZ {
		return nil, fmt.Errorf("fetcher: mismatched compression (%q) and content-type (%q)", kind.String(), ct)
	}

	buf := bufio.NewWriter(f)
	n, err := io.Copy(buf, zr)
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

	rc := newRc(f, func() {
		a.rc.Delete(key)
	})
	if _, ok := a.rc.Swap(key, rc); ok {
		rc.Ref().Close()
		return nil, fmt.Errorf("fetcher: double-store for key %q", key)
	}

	zlog.Debug(ctx).Msg("layer fetch ok")
	span.SetStatus(codes.Ok, "")
	return rc, nil
}

// Close forgets all references in the arena.
//
// Any outstanding Layers may cause keys to be forgotten at unpredictable times.
func (a *RemoteFetchArena) Close(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/fetchArena.Close",
		"arena", a.root)
	a.rc.Range(func(k, _ any) bool {
		a.rc.Delete(k)
		return true
	})
	return nil
}

// Realizer returns an indexer.Realizer.
//
// The concrete return type is [*FetchProxy].
func (a *RemoteFetchArena) Realizer(_ context.Context) indexer.Realizer {
	return &FetchProxy{a: a}
}

// FetchProxy tracks the files fetched for layers.
type FetchProxy struct {
	a       *RemoteFetchArena
	cleanup []io.Closer
}

// Realize populates all the layers locally.
//
// Deprecated: This method proxies to [FetchProxy.RealizeDescriptions] via
// copies and a (potentially expensive) comparison operation. Callers should use
// [FetchProxy.RealizeDescriptions] if they already have the
// [claircore.LayerDescription] constructed.
func (p *FetchProxy) Realize(ctx context.Context, ls []*claircore.Layer) error {
	ds := wart.LayersToDescriptions(ls)
	ret, err := p.RealizeDescriptions(ctx, ds)
	if err != nil {
		return err
	}
	wart.CopyLayerPointers(ls, ret)
	return nil
}

// RealizeDesciptions returns [claircore.Layer] structs populated according to
// the passed slice of [claircore.LayerDescription].
func (p *FetchProxy) RealizeDescriptions(ctx context.Context, descs []claircore.LayerDescription) ([]claircore.Layer, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/FetchProxy.RealizeDescriptions")
	ctx, span := tracer.Start(ctx, "RealizeDescriptions")
	defer span.End()
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
	ls := make([]claircore.Layer, len(descs))
	cleanup := make([]io.Closer, len(descs))

	for i := range descs {
		g.Go(p.a.fetchInto(ctx, &ls[i], &cleanup[i], &descs[i]))
	}

	if e := g.Wait(); e != nil {
		err := fmt.Errorf("fetcher: encountered errors: %w", e)
		cl := make([]error, 0, len(p.cleanup))
		for _, c := range cleanup {
			if c != nil {
				cl = append(cl, c.Close())
			}
		}
		if cl := errors.Join(cl...); cl != nil {
			err = fmt.Errorf("%w; while cleaning up: %w", err, cl)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, "RealizeDescriptions errored")
		return nil, err
	}
	p.cleanup = cleanup
	span.SetStatus(codes.Ok, "")
	return ls, nil
}

// Close marks all the files backing any returned [claircore.Layer] as unused.
//
// This method may delete the backing files, necessitating them being fetched by
// a subsequent call to [FetchProxy.RealizeDescriptions].
func (p *FetchProxy) Close() error {
	errs := make([]error, len(p.cleanup))
	for i, c := range p.cleanup {
		if c != nil {
			errs[i] = c.Close()
		}
	}
	return errors.Join(errs...)
}
