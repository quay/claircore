package libindex

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/ctxlock"
)

const versionMagic = "libindex number: 2\n"

// Libindex implements the method set for scanning and indexing a Manifest.
type Libindex struct {
	// holds dependencies for creating a libindex instance
	*Opts
	// a Store which will be shared between scanner instances
	store indexer.Store
	// a shareable http client
	client *http.Client
	// Cl provides system-wide locks.
	cl *ctxlock.Locker
	// an opaque and unique string representing the configured
	// state of the indexer. see setState for more information.
	state string
	// FetchArena is an arena to fetch layers into. It ensures layers are
	// fetched once and not removed while in use.
	fetchArena FetchArena
}

// New creates a new instance of libindex.
//
// The passed http.Client will be used for fetching layers and any HTTP requests
// made by scanners.
func New(ctx context.Context, opts *Opts, cl *http.Client) (*Libindex, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libindex/New"))
	err := opts.Parse(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse opts: %v", err)
	}
	if cl == nil {
		return nil, errors.New("invalid *http.Client")
	}
	// TODO(hank) If "airgap" is set, we should wrap the client and return
	// errors on non-RFC1918 and non-RFC4193 addresses. As of go1.17, the net.IP
	// type has a method for this purpose.

	dbPool, err := initDB(ctx, opts)
	if err != nil {
		return nil, err
	}
	zlog.Info(ctx).Msg("created database connection")

	store, err := initStore(ctx, dbPool, opts)
	if err != nil {
		return nil, err
	}

	ctxLocker, err := ctxlock.New(ctx, dbPool)
	if err != nil {
		return nil, err
	}

	l := &Libindex{
		Opts:   opts,
		store:  store,
		client: cl,
		cl:     ctxLocker,
	}
	l.fetchArena.Init(cl, os.TempDir()) // TODO(hank) Add an option field for this 'root' argument.

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
	l.Opts.vscnrs = vscnrs
	return l, nil
}

// Close releases held resources.
func (l *Libindex) Close(ctx context.Context) error {
	l.cl.Close(ctx)
	l.store.Close(ctx)
	l.fetchArena.Close(ctx)
	return nil
}

// Index performs a scan and index of each layer within the provided Manifest.
//
// If the index operation cannot start an error will be returned.
// If an error occurs during scan the error will be propagated inside the IndexReport.
func (l *Libindex) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libindex/Libindex.Index"),
		label.Stringer("manifest", manifest.Hash))
	zlog.Info(ctx).Msg("index request start")
	defer zlog.Info(ctx).Msg("index request done")
	c, err := l.ControllerFactory(ctx, l, l.Opts)
	if err != nil {
		return nil, fmt.Errorf("scanner factory failed to construct a scanner: %v", err)
	}

	zlog.Debug(ctx).Msg("locking attempt")
	lc, done := l.cl.Lock(ctx, manifest.Hash.String())
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "libindex/Libindex.AffectedManifests"))

	affected := claircore.NewAffectedManifests()
	errGrp, eCTX := errgroup.WithContext(ctx)
	for i := 0; i < len(vulns); i++ {
		ii := i

		do := func() error {
			defer sem.Release(1)
			if eCTX.Err() != nil {
				return eCTX.Err()
			}
			hashes, err := l.store.AffectedManifests(eCTX, vulns[ii])
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
