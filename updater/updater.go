package updater

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	driver "github.com/quay/claircore/updater/driver/v1"
)

// Updater coordinates running Updaters and saving the results.
//
// Close must be called, or the program may panic.
type Updater struct {
	store     Store
	locker    Locker
	client    *http.Client
	configs   driver.Configs
	factories []driver.UpdaterFactory
}

// New returns an Updater ready to use.
//
// None of the resources passed in the Options struct have any of their cleanup
// methods called, and need to be safe for use by multiple goroutines.
func New(ctx context.Context, opts *Options) (*Updater, error) {
	if opts.Store == nil {
		return nil, errors.New("updater: no Store implementation provided")
	}
	if opts.Client == nil {
		return nil, errors.New("updater: no http.Client provided")
	}

	u := &Updater{
		store:     opts.Store,
		locker:    opts.Locker,
		client:    opts.Client,
		configs:   opts.Configs,
		factories: opts.Factories,
	}

	if opts.Locker == nil {
		zlog.Warn(ctx).Msg("no locker passed, using process-local locking")
		u.locker = newLocalLocker()
	}
	if opts.Configs == nil {
		zlog.Info(ctx).Msg("no updater configuration passed")
		u.configs = make(driver.Configs)
	}
	if opts.Factories == nil {
		zlog.Warn(ctx).Msg("no updater factories provided, this may be a misconfiguration")
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(u, func(u *Updater) {
		panic(fmt.Sprintf("%s:%d: Updater not closed", file, line))
	})
	return u, nil
}

// Close releases any resources held by the Updater.
func (u *Updater) Close() error {
	runtime.SetFinalizer(u, nil)
	u.store = nil
	u.locker = nil
	u.client = nil
	u.configs = nil
	u.factories = nil
	return nil
}

// Options contains the needed options for an Updater.
//
// The Store and Client members are required. The others are optional, but
// should only be omitted in specific circumstances.
type Options struct {
	// This should disallow an unkeyed literal and means that additions to the
	// struct shouldn't cause compilation errors.
	_forceKeys struct{}
	// Store is the interface used to persist parsed data.
	Store Store
	// Client is the http.Client all the Updaters will use.
	Client *http.Client

	// Locker provides system-wide locks. If multiple Updater processes are
	// running, this should be backed by a distributed lock manager.
	Locker Locker
	// Configs holds configuration functions for Updaters.
	Configs driver.Configs
	// Factories is a slice of UpdaterFactories that are used to construct
	// Updaters on demand.
	Factories []driver.UpdaterFactory
}

// All the internal machinery deals with this taggedUpdater type, so that we
// only have to call the Name method once.
//
// This is to avoid having lots of labeled calls, as *all* calls to updaters
// should be labeled to help in debugging stray goroutines.
type taggedUpdater struct {
	Name    string
	Updater driver.Updater
}

// Run constructs new updaters, runs them, and stores the results.
//
// Errors reported from the Updater itself will return the error immediately,
// but errors reported from updaters are collected and reported once all
// updaters have run.
//
// Run should be preferred to explicit Fetch and Parse calls, because knowing
// that both methods will be running in the same process allows for better
// resource usage.
func (u *Updater) Run(ctx context.Context, strict bool) error {
	var (
		us  []taggedUpdater
		ops []driver.UpdateOperation
	)
	sg, sctx := errgroup.WithContext(ctx)
	sg.Go(func() (err error) {
		us, err = u.updaters(sctx, u.configs)
		return err
	})
	sg.Go(func() (err error) {
		ops, err = u.store.GetLatestUpdateOperations(sctx)
		return err
	})
	if err := sg.Wait(); err != nil {
		return err
	}
	pfps := make(map[string]driver.Fingerprint, len(ops))
	for _, op := range ops {
		pfps[op.Updater] = op.Fingerprint
	}

	var wg sync.WaitGroup
	lim := runtime.GOMAXPROCS(0)
	wg.Add(lim)
	feed, errCh := make(chan taggedUpdater), make(chan error)
	var errs []error

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(feeder(ctx, feed, us))
	eg.Go(func() error {
		wg.Wait()
		close(errCh)
		return nil
	})
	eg.Go(func() error {
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil
	})
	for i := 0; i < lim; i++ {
		eg.Go(func() error {
			defer wg.Done()
			spool, err := os.CreateTemp(tmpDir, tmpPattern)
			if err != nil {
				zlog.Warn(ctx).Err(err).Msg("unable to create spool file")
				return err
			}
			spoolname := spool.Name()
			defer func() {
				if err := os.Remove(spoolname); err != nil {
					zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("unable to remove spool file")
				}
				if err := spool.Close(); err != nil {
					zlog.Warn(ctx).Str("filename", spoolname).Err(err).Msg("error closing spool file")
				}
			}()
			var updErr *updaterError
			for upd := range feed {
				err := u.fetchAndParse(ctx, spool, pfps, upd)
				switch {
				case errors.Is(err, nil):
				case errors.As(err, &updErr):
					zlog.Debug(ctx).Err(updErr).Msg("updater error")
					errCh <- updErr.Unwrap()
				default:
					return err
				}
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	// Print or return errors.
	if len(errs) != 0 {
		if strict {
			return errSlice(errs)
		}
		zlog.Info(ctx).Errs("errors", errs).Msg("updater errors")
	}
	return nil
}

// In all cases, calls into Updaters should be done with the goroutine labels
// set. This allows an execution trace to help narrow down any orphaned
// goroutines.

func (u *Updater) updaters(ctx context.Context, cfg driver.Configs) ([]taggedUpdater, error) {
	var r []taggedUpdater
	dedup := make(map[string]struct{})
	for _, fac := range u.factories {
		var key string
		pprof.Do(ctx, pprof.Labels("task", "factory_name"), func(_ context.Context) {
			key = fac.Name()
		})
		var set []driver.Updater
		var err error
		pprof.Do(ctx, pprof.Labels("task", "factory_create", "factory", key), func(ctx context.Context) {
			set, err = fac.Create(ctx, cfg[key])
		})
		if err != nil {
			zlog.Info(ctx).Err(err).Msg("factory errored")
			continue
		}
		for _, upd := range set {
			var name string
			pprof.Do(ctx, pprof.Labels("task", "updater_name"), func(_ context.Context) {
				name = upd.Name()
			})
			if strings.Contains(name, "/") {
				zlog.Info(ctx).Str("updater", name).Msg("name contains invalid character: /")
				continue
			}
			if _, ok := dedup[name]; ok {
				zlog.Info(ctx).Str("updater", name).Msg("updater already exists")
				continue
			}
			dedup[name] = struct{}{}
			r = append(r, taggedUpdater{
				Name:    name,
				Updater: upd,
			})
		}
	}
	sort.Slice(r, func(i, j int) bool { return r[i].Name < r[j].Name })
	return r, nil
}

func (u *Updater) fetchOne(ctx context.Context, tu taggedUpdater, pfp driver.Fingerprint, out io.Writer) (fp driver.Fingerprint, err error) {
	name := tu.Name
	ctx = zlog.ContextWithValues(ctx, "updater", name)
	zlog.Info(ctx).Msg("fetch start")
	defer zlog.Info(ctx).Msg("fetch done")
	lctx, done := u.locker.TryLock(ctx, name)
	defer done()
	if err := lctx.Err(); err != nil {
		if pErr := ctx.Err(); pErr != nil {
			zlog.Debug(ctx).Err(err).Msg("parent context canceled")
			return fp, nil
		}
		zlog.Info(ctx).Err(err).Msg("lock acquisition failed, skipping")
		return fp, err
	}
	ctx = lctx

	zw := zip.NewWriter(out)
	defer func() {
		if err := zw.Close(); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unable to close zip writer")
		}
	}()
	if len(pfp) != 0 {
		zlog.Debug(ctx).Str("fingerprint", string(pfp)).Msg("found previous fingerprint")
	}
	pprof.Do(ctx, pprof.Labels("task", "updater_fetch", "updater", name), func(ctx context.Context) {
		fp, err = tu.Updater.Fetch(ctx, zw, pfp, u.client)
	})
	return fp, err
}

func (u *Updater) parseOne(ctx context.Context, tu taggedUpdater, in fs.FS) (*parseResult, error) {
	var (
		any bool
		res parseResult
		err error
	)
	name := tu.Name
	ctx = zlog.ContextWithValues(ctx, "updater", name)
	zlog.Info(ctx).Msg("parse start")
	defer zlog.Info(ctx).Msg("parse done")

	pprof.Do(ctx, pprof.Labels("task", "updater_parse", "updater", name), func(ctx context.Context) {
		ctx = zlog.ContextWithValues(ctx, "updater", name)
		upd := tu.Updater
		if p, ok := upd.(driver.VulnerabilityParser); ok {
			zlog.Debug(ctx).Msg("implements VulnerabilityParser")
			any = true
			res.Vulnerabilities, err = p.ParseVulnerability(ctx, in)
			if err != nil {
				return
			}
			zlog.Debug(ctx).
				Err(err).
				Int("ct", len(res.Vulnerabilities.Vulnerability)).
				Msg("found vulnerabilities")
		}
		if p, ok := upd.(driver.EnrichmentParser); ok {
			zlog.Debug(ctx).Msg("implements EnrichmentParser")
			any = true
			res.Enrichments, err = p.ParseEnrichment(ctx, in)
			if err != nil {
				return
			}
			zlog.Debug(ctx).
				Err(err).
				Int("ct", len(res.Enrichments)).
				Msg("found enrichments")
		}
	})
	if !any {
		return nil, errors.New("did nothing")
	}
	return &res, nil
}

type parseResult struct {
	Vulnerabilities *driver.ParsedVulnerabilities
	Enrichments     []driver.EnrichmentRecord
}

func (u *Updater) fetchAndParse(ctx context.Context, spool *os.File, pfps map[string]driver.Fingerprint, tu taggedUpdater) error {
	spoolname := spool.Name()
	name := tu.Name
	ctx = zlog.ContextWithValues(ctx, "updater", name)
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		zlog.Error(ctx).Str("filename", spoolname).Err(err).Msg("unable to seek to start")
		return err
	}
	fp, err := u.fetchOne(ctx, tu, pfps[name], spool)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, driver.ErrUnchanged):
		zlog.Debug(ctx).Msg("unchanged")
		return nil
	default:
		return updaterErr(err)
	}
	sz, err := spool.Seek(0, io.SeekCurrent)
	if err != nil {
		zlog.Error(ctx).Str("filename", spoolname).Err(err).Msg("unable to seek spoolfile")
		return err
	}
	z, err := zip.NewReader(spool, sz)
	if err != nil {
		zlog.Error(ctx).Str("filename", spoolname).Err(err).Msg("unable to create zip reader")
		return err
	}
	res, err := u.parseOne(ctx, tu, z)
	if err != nil {
		return updaterErr(err)
	}
	ref := uuid.New()

	pprof.Do(ctx, pprof.Labels("updater", name), func(ctx context.Context) {
		if len(res.Vulnerabilities.Vulnerability) != 0 {
			err = u.store.UpdateVulnerabilities(ctx, ref, name, fp, res.Vulnerabilities)
			if err != nil {
				return
			}
			zlog.Info(ctx).Stringer("ref", ref).Msg("updated vulnerabilites")
		}
		if len(res.Enrichments) != 0 {
			err = u.store.UpdateEnrichments(ctx, ref, name, fp, res.Enrichments)
			if err != nil {
				return
			}
			zlog.Info(ctx).Stringer("ref", ref).Msg("updated enrichments")
		}
	})
	if err != nil {
		return err
	}
	return nil
}

// UpdaterErr returns an *updaterError wrapping "e".
//
// This is used to signal when an error came from an updater.
func updaterErr(e error) error {
	return &updaterError{orig: e}
}

type updaterError struct {
	orig error
}

func (u *updaterError) Error() string {
	return u.orig.Error()
}

func (u *updaterError) Unwrap() error {
	return u.orig
}

// Feeder sends "us" down "ch" and closes it when done, while respecting the
// Context's timeout.
func feeder(ctx context.Context, ch chan<- taggedUpdater, us []taggedUpdater) func() error {
	return func() error {
		defer close(ch)
		for _, u := range us {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- u:
			}
		}
		return nil
	}
}

// ErrSlice implements error, for accumulating errors.
type errSlice []error

func (e errSlice) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	b.WriteString("updater errors:\n")
	for _, err := range e {
		b.WriteByte('\t')
		b.WriteString(err.Error())
		b.WriteByte('\n')
	}
	return b.String()
}

const (
	tmpDir     = ``
	tmpPattern = `updater.spool.*`
)
