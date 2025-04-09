package libindex

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/dpkg"
	"github.com/quay/claircore/gobin"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/indexer/controller"
	"github.com/quay/claircore/java"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/rpm"
	"github.com/quay/claircore/ruby"
	"github.com/quay/claircore/whiteout"
)

const versionMagic = "libindex number: 2\n"

// LockSource abstracts over how locks are implemented.
//
// An online system needs distributed locks, offline use cases can use
// process-local locks.
type LockSource interface {
	TryLock(context.Context, string) (context.Context, context.CancelFunc)
	Lock(context.Context, string) (context.Context, context.CancelFunc)
	Close(context.Context) error
}

// Libindex implements the method set for scanning and indexing a Manifest.
type Libindex struct {
	// holds dependencies for creating a libindex instance
	*Options
	// a store implementation which will be shared between scanner instances
	store indexer.Store
	// a shareable http client
	client *http.Client
	// Locker provides system-wide locks.
	locker LockSource
	// an opaque and unique string representing the configured
	// state of the indexer. see setState for more information.
	state string
	// FetchArena is an arena to fetch layers into. It ensures layers are
	// fetched once and not removed while in use.
	fa indexer.FetchArena
	// vscnrs is a convenience object for holding a list of versioned scanners
	vscnrs indexer.VersionedScanners
	// indexerOptions hold construction context for the layerScanner and the
	// controller factory.
	indexerOptions *indexer.Options
}

// New creates a new instance of libindex.
//
// The passed http.Client will be used for fetching layers and any HTTP requests
// made by scanners.
func New(ctx context.Context, opts *Options, cl *http.Client) (*Libindex, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "libindex/New")
	// required
	if opts.Locker == nil {
		return nil, fmt.Errorf("field Locker cannot be nil")
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("field Store cannot be nil")
	}
	if opts.FetchArena == nil {
		return nil, fmt.Errorf("field FetchArena cannot be nil")
	}

	// optional
	if (opts.ScanLockRetry == 0) || (opts.ScanLockRetry < time.Second) {
		opts.ScanLockRetry = DefaultScanLockRetry
	}
	if opts.LayerScanConcurrency == 0 {
		opts.LayerScanConcurrency = DefaultLayerScanConcurrency
	}
	if opts.ControllerFactory == nil {
		opts.ControllerFactory = controller.New
	}
	if opts.Ecosystems == nil {
		opts.Ecosystems = []*indexer.Ecosystem{
			dpkg.NewEcosystem(ctx),
			alpine.NewEcosystem(ctx),
			rhel.NewEcosystem(ctx),
			rpm.NewEcosystem(ctx),
			python.NewEcosystem(ctx),
			java.NewEcosystem(ctx),
			rhcc.NewEcosystem(ctx),
			gobin.NewEcosystem(ctx),
			ruby.NewEcosystem(ctx),
		}
	}
	// Add whiteout objects
	// Always add the whiteout ecosystem
	opts.Ecosystems = append(opts.Ecosystems, whiteout.NewEcosystem(ctx))
	opts.Resolvers = []indexer.Resolver{
		&whiteout.Resolver{},
	}

	if cl == nil {
		return nil, errors.New("invalid *http.Client")
	}

	l := &Libindex{
		Options: opts,
		client:  cl,
		store:   opts.Store,
		locker:  opts.Locker,
		fa:      opts.FetchArena,
	}

	// register any new scanners.
	pscnrs, dscnrs, rscnrs, fscnrs, err := indexer.EcosystemsToScanners(ctx, opts.Ecosystems)
	if err != nil {
		return nil, err
	}
	vscnrs := indexer.MergeVS(pscnrs, dscnrs, rscnrs, fscnrs)

	err = l.store.RegisterScanners(ctx, vscnrs)
	if err != nil {
		return nil, fmt.Errorf("failed to register configured scanners: %v", err)
	}

	// set the indexer's state
	err = l.setState(ctx, vscnrs)
	if err != nil {
		return nil, fmt.Errorf("failed to set the indexer state: %v", err)
	}

	zlog.Info(ctx).Msg("registered configured scanners")
	l.vscnrs = vscnrs

	// create indexer.Options
	l.indexerOptions = &indexer.Options{
		Store:         l.store,
		FetchArena:    l.fa,
		Ecosystems:    opts.Ecosystems,
		Vscnrs:        l.vscnrs,
		Client:        l.client,
		ScannerConfig: opts.ScannerConfig,
		Resolvers:     opts.Resolvers,
	}
	l.indexerOptions.LayerScanner, err = indexer.NewLayerScanner(ctx, opts.LayerScanConcurrency, l.indexerOptions)
	if err != nil {
		return nil, err
	}

	return l, nil
}

// Close releases held resources.
func (l *Libindex) Close(ctx context.Context) error {
	l.locker.Close(ctx)
	l.store.Close(ctx)
	l.fa.Close(ctx)
	return nil
}

// Index performs a scan and index of each layer within the provided Manifest.
//
// If the index operation cannot start an error will be returned.
// If an error occurs during scan the error will be propagated inside the IndexReport.
func (l *Libindex) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "libindex/Libindex.Index",
		"manifest", manifest.Hash.String())
	zlog.Info(ctx).Msg("index request start")
	defer zlog.Info(ctx).Msg("index request done")

	zlog.Debug(ctx).Msg("locking attempt")
	lc, done := l.locker.Lock(ctx, manifest.Hash.String())
	defer done()
	// The process may have waited on the lock, so check that the context is
	// still active.
	if err := lc.Err(); !errors.Is(err, nil) {
		return nil, err
	}
	zlog.Debug(ctx).Msg("locking OK")
	c := l.ControllerFactory(l.indexerOptions)
	return c.Index(lc, manifest)
}

// State returns an opaque identifier identifying how the struct is currently
// configured.
//
// If the identifier has changed, clients should arrange for layers to be
// re-indexed.
func (l *Libindex) State(ctx context.Context) (string, error) {
	return l.state, nil
}

// setState creates a unique and opaque identifier representing the indexer's
// configuration state.
//
// Indexers running different scanner versions will produce different state strings.
// Thus this state value can be used as a cue for clients to re-index their manifests
// and obtain a new IndexReport.
func (l *Libindex) setState(ctx context.Context, vscnrs indexer.VersionedScanners) error {
	h := md5.New()
	var ns []string
	m := make(map[string][]byte)
	for _, s := range vscnrs {
		n := s.Name()
		m[n] = []byte(n + s.Version() + s.Kind() + "\n")
		// TODO(hank) Should this take into account configuration? E.g. If a
		// scanner implements the configurable interface, should we expect that
		// we can serialize the scanner's concrete type?
		ns = append(ns, n)
	}
	if _, err := io.WriteString(h, versionMagic); err != nil {
		return err
	}
	sort.Strings(ns)
	for _, n := range ns {
		if _, err := h.Write(m[n]); err != nil {
			return err
		}
	}
	l.state = hex.EncodeToString(h.Sum(nil))
	return nil
}

// IndexReport retrieves an IndexReport for a particular manifest hash, if it exists.
func (l *Libindex) IndexReport(ctx context.Context, hash claircore.Digest) (*claircore.IndexReport, bool, error) {
	return l.store.IndexReport(ctx, hash)
}

// AffectedManifests retrieves a list of affected manifests when provided a list of vulnerabilities.
func (l *Libindex) AffectedManifests(ctx context.Context, vulns []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "libindex/Libindex.AffectedManifests")

	affected := claircore.NewAffectedManifests()
	g, ctx := errgroup.WithContext(ctx)
	// TODO(hank) Look in the git history and see if there's any hint where this
	// number comes from. I suspect it's a WAG constant.
	g.SetLimit(20)
	do := func(i int) func() error {
		return func() error {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			default:
			}
			hashes, err := l.store.AffectedManifests(ctx, vulns[i])
			if err != nil {
				return err
			}
			affected.Add(&vulns[i], hashes...)
			return nil
		}
	}
V:
	for i := 0; i < len(vulns); i++ {
		g.Go(do(i))
		select {
		case <-ctx.Done():
			break V
		default:
		}
	}
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("received error retrieving affected manifests: %w", err)
	}
	affected.Sort()
	return &affected, nil
}

// DeleteManifests removes manifests specified by the provided digests.
//
// Providing an unknown digest is not an error.
func (l *Libindex) DeleteManifests(ctx context.Context, d ...claircore.Digest) ([]claircore.Digest, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "libindex/Libindex.DeleteManifests")
	return l.store.DeleteManifests(ctx, d...)
}
