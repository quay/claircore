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
	"runtime"
	"strings"
	"sync"
	"unique"
	"weak"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/httputil"
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
	sf singleflight.Group

	// Layers is a map[unique.Handle[string]][weak.Pointer[layerFile]]
	// where the key is the layer digest and the value points to a file
	// with the layer's contents.
	layers sync.Map
	root   string
}

// NewRemoteFetchArena returns an initialized RemoteFetchArena.
//
// If the "root" parameter is "", the advice in [file-hierarchy(7)] and ["Using
// /tmp/ and /var/tmp/ Safely"] is followed. Specifically, "/var/tmp" is used
// unless "TMPDIR" is set in the environment, in which case the contents of that
// variable are interpreted as a path and used.
//
// The RemoteFetchArena attempts to use [O_TMPFILE] and falls back to
// [os.CreateTemp] if that seems to not work. If the filesystem backing "root"
// does not support O_TMPFILE, files may linger in the event of a process
// crashing or an unclean shutdown. Operators should either use a different
// filesystem or arrange for periodic cleanup via [systemd-tmpfiles(8)] or
// similar.
//
// In a containerized environment, operators may need to mount a directory or
// filesystem on "/var/tmp".
//
// On OSX, temporary files are not unlinked from the filesystem upon creation,
// because an equivalent to Linux's "/proc/self/fd" doesn't seem to exist.
//
// On UNIX-unlike systems, none of the above logic takes place.
//
// [file-hierarchy(7)]: https://www.freedesktop.org/software/systemd/man/latest/file-hierarchy.html
// ["Using /tmp/ and /var/tmp/ Safely"]: https://systemd.io/TEMPORARY_DIRECTORIES/
// [O_TMPFILE]: https://man7.org/linux/man-pages/man2/open.2.html
// [systemd-tmpfiles(8)]: https://www.freedesktop.org/software/systemd/man/latest/systemd-tmpfiles.html
func NewRemoteFetchArena(wc *http.Client, root string) *RemoteFetchArena {
	return &RemoteFetchArena{
		wc:   wc,
		root: fixTemp(root),
	}
}

// LayerFile is a wrapper around a tempFile which
// automatically cleans the tempFile upon gc.
type layerFile struct {
	*tempFile
}

// NewLayerFile creates a new file to hold a container image layer's contents.
func newLayerFile(f *tempFile) *layerFile {
	lf := &layerFile{tempFile: f}
	runtime.AddCleanup(lf, func(f *tempFile) {
		_ = f.Close()
	}, f)
	return lf
}

// FetchInto populates "l" and "cl" via a [singleflight.Group].
//
// It returns a closure to be used with an [errgroup.Group]
func (a *RemoteFetchArena) fetchInto(ctx context.Context, l *claircore.Layer, cl *io.Closer, desc *claircore.LayerDescription) (do func() error) {
	key := unique.Make(desc.Digest)
	do = func() error {
		ctx, span := tracer.Start(ctx, "RemoteFetchArena.fetchInto", trace.WithAttributes(attribute.String("key", key.Value())))
		defer span.End()
		var lf *layerFile
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

		for {
			v, ok := a.layers.Load(key)
			if ok {
				lf = v.(weak.Pointer[layerFile]).Value()
				if lf != nil {
					break
				}
				// The weak pointer has been gc'd,
				// so delete and try again.
				a.layers.CompareAndDelete(key, v)
			} else {
				ch := a.sf.DoChan(key.Value(), func() (any, error) {
					return a.fetchUnlinkedFile(ctx, key, desc)
				})
				select {
				case <-ctx.Done():
					err = context.Cause(ctx)
					return err
				case res := <-ch:
					if e := res.Err; e != nil {
						err = fmt.Errorf("error realizing layer %s: %w", key.Value(), e)
						return err
					}
					lf = res.Val.(*layerFile)
					span.AddEvent("got value from singleflight")
					span.SetAttributes(attribute.Bool("shared", res.Shared))
					break
				}
			}
		}

		// Re-open the file containing the layer contents.
		// We don't bother explicitly calling the file's Close method,
		// as it is implicitly handled once lf is deleted from the map and
		// subsequently gc'd.
		f, err := lf.Reopen()
		if err != nil {
			return err
		}

		if err := l.Init(ctx, desc, f); err != nil {
			return err
		}
		*cl = closeFunc(func() error {
			return l.Close()
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
// Because we know we're the only concurrent call dealing with this key,
// we can be a bit more lax.
func (a *RemoteFetchArena) fetchUnlinkedFile(ctx context.Context, key unique.Handle[string], desc *claircore.LayerDescription) (*layerFile, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/fetchArena.fetchUnlinkedFile",
		"arena", a.root,
		"layer", desc.Digest,
		"uri", desc.URI)
	ctx, span := tracer.Start(ctx, "RemoteFetchArena.fetchUnlinkedFile")
	defer span.End()
	span.SetStatus(codes.Error, "")
	zlog.Debug(ctx).Msg("layer fetch start")

	// It is possible another goroutine added this key to the map before we got here.
	// Do one more check to confirm if we really have to pull the layer.
	if v, ok := a.layers.Load(key); ok {
		if lf := v.(weak.Pointer[layerFile]).Value(); lf != nil {
			zlog.Debug(ctx).Msg("layer fetch ok")
			span.SetStatus(codes.Ok, "")
			return lf, nil
		}
		a.layers.CompareAndDelete(key, v)
	}

	// We know for sure the key for this layer is not in the map,
	// so we definitely have to pull the contents.

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
	err = httputil.CheckResponse(resp, http.StatusOK)
	if err != nil {
		return nil, err
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

	lf := newLayerFile(f)
	wp := weak.Make(lf)
	runtime.AddCleanup(f, func(key unique.Handle[string]) {
		a.layers.CompareAndDelete(key, wp)
	}, key)
	a.layers.Store(key, wp)

	zlog.Debug(ctx).Msg("layer fetch ok")
	span.SetStatus(codes.Ok, "")
	return lf, nil
}

// Close forgets all references in the arena.
//
// Any outstanding Layers may cause keys to be forgotten at unpredictable times.
func (a *RemoteFetchArena) Close(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/fetchArena.Close",
		"arena", a.root)
	a.layers.Clear()
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

// RealizeDescriptions returns [claircore.Layer] structs populated according to
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
