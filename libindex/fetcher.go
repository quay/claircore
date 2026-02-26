package libindex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/cache"
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

	// The string is a layer digest.
	files cache.Live[string, os.File]
	root  *os.Root
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
	name := fixTemp(root)
	dir, err := os.OpenRoot(name)
	if err != nil {
		// Backed ourselves into a corner on this API 🙃
		panic(fmt.Errorf("fetcher: unable to OpenRoot(%q): %w", root, err))
	}
	a := &RemoteFetchArena{
		wc:   wc,
		root: dir,
	}
	return a
}

// FetchInto populates "l" and "cl" via a cache.
//
// It returns a closure to be used with an [errgroup.Group]
func (a *RemoteFetchArena) fetchInto(ctx context.Context, l *claircore.Layer, cl *io.Closer, desc *claircore.LayerDescription) (do func() error) {
	key := desc.Digest

	return func() (err error) {
		ctx, span := tracer.Start(ctx, "RemoteFetchArena.fetchInto", trace.WithAttributes(attribute.String("key", key)))
		defer span.End()
		defer func() {
			span.RecordError(err)
			if err == nil {
				span.SetStatus(codes.Ok, "")
			} else {
				span.SetStatus(codes.Error, "fetchInto error")
			}
		}()

		// NB This is not closed on purpose. The [io.Closer] populated by this
		// function holds the pointer until that function is cleaned up. Once
		// nothing has a copy of this [*os.File], the runtime will run all the
		// cleanup logic associated with the pointer.
		//
		// Every new [*claircore.Layer] gets its own file descriptor via the
		// [reopen] helper.
		var spool *os.File
		spool, err = a.files.Get(ctx, key, func(ctx context.Context, _ string) (*os.File, error) {
			return a.fetchFileForCache(ctx, desc)
		})
		if err != nil {
			return err
		}
		// This is an owned, independent descriptor for the passed [*os.File].
		f, err := reopen(a.root, spool)
		if err != nil {
			return err
		}

		// If this succeeds, "f" is now owned by "l"
		if err := l.Init(ctx, desc, f); err != nil {
			return errors.Join(err, f.Close())
		}
		*cl = closeFunc(func() (err error) {
			err = errors.Join(l.Close(), f.Close())
			// Using this KeepAlive keeps the cached file descriptor live until
			// all users of the blob have cleaned up. This should be after "f"
			// is closed so that the cached-owned file descriptor outlives any
			// reopened copies. There's no explicit association of these file
			// descriptors, it's all kernel-side book-keeping.
			runtime.KeepAlive(spool)
			return err
		})

		return nil
	}
}

// CloseFunc is an adapter in the vein of [http.HandlerFunc].
type closeFunc func() error

// Close implements [io.Closer].
func (f closeFunc) Close() error {
	return f()
}

// FetchFileForCache is the inner function used inside the [cache.Live].
//
// Because we know we're the only concurrent call that's dealing with this blob,
// we can be a bit more lax.
func (a *RemoteFetchArena) fetchFileForCache(ctx context.Context, desc *claircore.LayerDescription) (*os.File, error) {
	log := slog.With("arena", a.root.Name(), "layer", desc.Digest, "uri", desc.URI)
	ctx, span := tracer.Start(ctx, "RemoteFetchArena.fetchUnlinkedFile")
	defer span.End()
	span.SetStatus(codes.Error, "")
	log.DebugContext(ctx, "layer fetch start")

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
	log.DebugContext(ctx, "reported content-type", "content-type", ct)
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
		log.DebugContext(ctx, "fixed content-type", "content-type", ct)
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

	f, err := openTemp(a.root)
	if err != nil {
		return nil, err
	}
	// Track whether the file was fully populated.
	// Doing this (instead of waiting for GC to clean up the fd associated with
	// the [*os.File]) allows the system to eagerly reclaim disk space and
	// handle disk contention better.
	fileOK := false
	defer func() {
		if fileOK {
			return
		}
		if err := f.Close(); err != nil {
			log.WarnContext(ctx, "error closing spoolfile in error return", "reason", err)
		}
	}()
	buf := bufio.NewWriter(f)
	n, err := io.Copy(buf, zr)
	log.DebugContext(ctx, "wrote file", "size", n, "big", n >= bigLayerSize, "copy_error", err)
	// TODO(hank) Add a metric for "big files" and a histogram for size.
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

	log.DebugContext(ctx, "layer fetch ok")
	span.SetStatus(codes.Ok, "")
	fileOK = true
	return f, nil
}

const bigLayerSize = 1024 * 1024 * 1024 // 1 GiB

// Close forgets all references in the arena.
//
// Any outstanding Layers may cause keys to be forgotten at unpredictable times.
func (a *RemoteFetchArena) Close(_ context.Context) error {
	a.files.Clear()
	if err := a.root.Close(); err != nil {
		return fmt.Errorf("fetcher: RemoteFetchArena: unable to close os.Root: %w", err)
	}
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

func (p *FetchProxy) RealizeDescription(ctx context.Context, desc claircore.LayerDescription) (l claircore.Layer, cl io.Closer, err error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/FetchProxy.RealizeDescription")
	ctx, span := tracer.Start(ctx, "RealizeDescription")
	defer span.End()

	err = p.a.fetchInto(ctx, &l, &cl, &desc)()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "RealizeDescriptions errored")
	} else {
		span.SetStatus(codes.Ok, "")
	}
	return
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
