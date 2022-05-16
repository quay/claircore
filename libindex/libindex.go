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
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
	"github.com/quay/claircore/alpine"
	"github.com/quay/claircore/dpkg"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/java"
	"github.com/quay/claircore/pkg/omnimatcher"
	"github.com/quay/claircore/python"
	"github.com/quay/claircore/rhel"
	"github.com/quay/claircore/rhel/rhcc"
	"github.com/quay/claircore/rpm"
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
	fa Arena
	// vscnrs is a convenience object for holding a list of versioned scanners
	vscnrs indexer.VersionedScanners
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
		opts.ControllerFactory = controllerFactory
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
		}
	}

	// TODO(hank) If "airgap" is set, we should wrap the client and return
	// errors on non-RFC1918 and non-RFC4193 addresses. As of go1.17, the net.IP
	// type has a method for this purpose.
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
	pscnrs, dscnrs, rscnrs, err := indexer.EcosystemsToScanners(ctx, opts.Ecosystems, opts.Airgap)
	if err != nil {
		return nil, err
	}
	vscnrs := indexer.MergeVS(pscnrs, dscnrs, rscnrs)

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
	c, err := l.ControllerFactory(ctx, l, l.Options)
	if err != nil {
		return nil, fmt.Errorf("scanner factory failed to construct a scanner: %v", err)
	}

	zlog.Debug(ctx).Msg("locking attempt")
	lc, done := l.locker.Lock(ctx, manifest.Hash.String())
	defer done()
	// The process may have waited on the lock, so check that the context is
	// still active.
	if err := lc.Err(); !errors.Is(err, nil) {
		return nil, err
	}
	zlog.Debug(ctx).Msg("locking OK")

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
	sem := semaphore.NewWeighted(20)
	ctx = zlog.ContextWithValues(ctx, "component", "libindex/Libindex.AffectedManifests")
	om := omnimatcher.New(nil)

	affected := claircore.NewAffectedManifests()
	errGrp, eCTX := errgroup.WithContext(ctx)
	for i := 0; i < len(vulns); i++ {
		ii := i

		do := func() error {
			defer sem.Release(1)
			if eCTX.Err() != nil {
				return eCTX.Err()
			}
			hashes, err := l.store.AffectedManifests(eCTX, vulns[ii], om.Vulnerable)
			if err != nil {
				return err
			}
			affected.Add(&vulns[ii], hashes...)
			return nil
		}

		// Try to acquire the sem before starting the goroutine for bounded parallelism.
		if err := sem.Acquire(eCTX, 1); err != nil {
			return nil, err
		}
		errGrp.Go(do)
	}
	if err := errGrp.Wait(); err != nil {
		return &affected, fmt.Errorf("received error retrieving affected manifests: %v", err)
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
