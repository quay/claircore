package libindex

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/internal/indexer/controller"
)

const versionMagic = "libindex number: 1\n"

// Libindex implements the method set for scanning and indexing a Manifest.
type Libindex struct {
	// holds dependencies for creating a libindex instance
	*Opts
	// convenience field for creating scan-time resources that require a database
	db *sqlx.DB
	// a Store which will be shared between scanner instances
	store indexer.Store
	// a sharable http client
	client *http.Client
	state  string
}

// New creates a new instance of libindex
func New(ctx context.Context, opts *Opts) (*Libindex, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libindex/New").
		Logger()
	ctx = log.WithContext(ctx)
	err := opts.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse opts: %v", err)
	}

	db, store, err := initStore(ctx, opts)
	if err != nil {
		return nil, err
	}
	log.Info().Msg("created database connection")

	l := &Libindex{
		Opts:   opts,
		db:     db,
		store:  store,
		client: &http.Client{},
	}

	// register any new scanners.
	pscnrs, dscnrs, rscnrs, err := indexer.EcosystemsToScanners(ctx, opts.Ecosystems)
	vscnrs := indexer.MergeVS(pscnrs, dscnrs, rscnrs)

	h := md5.New()
	var ns []string
	m := make(map[string][]byte)
	for _, s := range vscnrs {
		n := s.Name()
		m[n] = []byte(n + s.Version() + s.Kind() + "\n")
		ns = append(ns, n)
	}
	if _, err := io.WriteString(h, versionMagic); err != nil {
		return nil, err
	}
	sort.Strings(ns)
	for _, n := range ns {
		if _, err := h.Write(m[n]); err != nil {
			return nil, err
		}
	}
	l.state = hex.EncodeToString(h.Sum(nil))

	err = l.store.RegisterScanners(ctx, vscnrs)
	if err != nil {
		return nil, fmt.Errorf("failed to register configured scanners: %v", err)
	}
	log.Info().Msg("registered configured scanners")
	l.Opts.vscnrs = vscnrs
	return l, nil
}

// Index performs a scan and index of each layer within the provided Manifest.
//
// If the index operation cannot start an error will be returned.
// If an error occurs during scan the error will be propagated inside the IndexReport.
func (l *Libindex) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libindex/Libindex.Index").
		Str("maifest", manifest.Hash).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("index request start")
	defer log.Info().Msg("index request done")
	c, err := l.ControllerFactory(l, l.Opts)
	if err != nil {
		return nil, fmt.Errorf("scanner factory failed to construct a scanner: %v", err)
	}
	rc := l.index(ctx, c, manifest)
	return rc, nil
}

// State returns an opaque identifier identifying how the struct is currently
// configured.
//
// If the identifier has changed, clients should arrange for layers to be
// re-indexed.
func (l *Libindex) State() string {
	return l.state
}

func (l *Libindex) index(ctx context.Context, s *controller.Controller, m *claircore.Manifest) *claircore.IndexReport {
	log := zerolog.Ctx(ctx).With().
		Str("component", "libindex/Libindex.index").
		Logger()
	ctx = log.WithContext(ctx)
	// attempt to get lock
	log.Debug().Msg("locking")
	// will block until available or ctx times out
	err := s.Lock(ctx, m.Hash)
	if err != nil {
		// something went wrong with getting a lock
		// this is not an error saying another process has the lock
		log.Error().
			Err(err).
			Msg("unexpected error acquiring lock")
		ir := &claircore.IndexReport{
			Success: false,
			Err:     fmt.Sprintf("unexpected error acquiring lock: %v", err),
		}
		// best effort to push to persistence since we are about to bail anyway
		_ = l.store.SetIndexReport(ctx, ir)
		return ir
	}
	defer log.Debug().Msg("unlocked")
	defer s.Unlock()
	log.Debug().Msg("locked")
	ir := s.Index(ctx, m)
	return ir
}

// IndexReport retrieves an IndexReport for a particular manifest hash, if it exists.
func (l *Libindex) IndexReport(ctx context.Context, hash string) (*claircore.IndexReport, bool, error) {
	res, ok, err := l.store.IndexReport(ctx, hash)
	return res, ok, err
}
