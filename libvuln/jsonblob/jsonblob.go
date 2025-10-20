// Package jsonblob implements a JSON-backed recording of update operations to
// replay later.
package jsonblob

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/datastore"
	"github.com/quay/claircore/libvuln/driver"
)

var _ datastore.Updater = (*Store)(nil)

// New constructs an empty Store.
func New() (*Store, error) {
	s := Store{}
	s.ops = make(map[string][]driver.UpdateOperation)
	s.entry = make(map[uuid.UUID]*Entry)
	s.latest = make(map[driver.UpdateKind]uuid.UUID)
	return &s, nil
}

// A Store buffers update operations.
//
// Store opens files in the OS-specified "temp" directories. If updates are
// sufficiently large, this may need to be adjusted. See [os.TempDir] for how to
// do so.
type Store struct {
	sync.RWMutex
	entry  map[uuid.UUID]*Entry
	ops    map[string][]driver.UpdateOperation
	latest map[driver.UpdateKind]uuid.UUID
}

// Load reads in all the records serialized in the provided [io.Reader].
func Load(ctx context.Context, r io.Reader) (*Store, error) {
	s, err := New()
	if err != nil {
		return nil, err
	}

	l, err := NewLoader(r)
	if err != nil {
		return nil, err
	}

	// TODO(DO NOT MERGE): ~~This implementation might be a bit naive. Currently,
	//  it basically copies [OfflineImport]. We could probably do some custom
	//  parsing such that it basically just decodes the json into the
	//  appropriate [Store] fields.~~
	//  Actually, this might be the way.
	//  [OfflineImport]: https://github.com/quay/claircore/blob/126f688bb11220fb34708719be91952dc32ff7b1/libvuln/updates.go#L17-L74
	for l.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e := l.Entry()
		if e.Enrichment != nil {
			if _, err = s.UpdateEnrichments(ctx, e.Updater, e.Fingerprint, e.Enrichment); err != nil {
				return nil, fmt.Errorf("updating enrichements: %w", err)
			}
		}
		if e.Vuln != nil {
			if _, err = s.UpdateVulnerabilities(ctx, e.Updater, e.Fingerprint, e.Vuln); err != nil {
				return nil, fmt.Errorf("updating vulnerabilities: %w", err)
			}
		}
	}
	if err := l.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

// Store writes out the contents of the receiver to the provided [io.Writer].
// It's the inverse of [Load].
//
// Store may only be called once for a series of [Store.UpdateVulnerabilities] and
// [Store.UpdateEnrichments] calls, as it deallocates resources as it writes them.
//
// It should be possible to call this as often as needed to flush resources to
// disk.
func (s *Store) Store(w io.Writer) error {
	s.RLock()
	defer s.RUnlock()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	write := func(id uuid.UUID, e CommonEntry) func(driver.UpdateKind, *os.File, int) error {
		return func(k driver.UpdateKind, f *os.File, ct int) error {
			if f == nil {
				return nil
			}
			defer f.Close()
			shim := newBufShim(f)
			defer shim.Close()
			for range ct {
				dent := diskEntry{
					CommonEntry: e,
					Ref:         id,
					Kind:        k,
				}
				switch k {
				case driver.EnrichmentKind:
					dent.Enrichment = shim
				case driver.VulnerabilityKind:
					dent.Vuln = shim
				default:
					panic(fmt.Sprintf("programmer error: unknown kind: %v", k))
				}
				if err := enc.Encode(&dent); err != nil {
					return err
				}
			}
			return nil
		}
	}

	for id, e := range s.entry {
		f := write(id, e.CommonEntry)
		verr := f(driver.VulnerabilityKind, e.vulns, e.vulnCt)
		eerr := f(driver.EnrichmentKind, e.enrichments, e.enrichmentCt)
		delete(s.entry, id)
		if err := errors.Join(verr, eerr); err != nil {
			return err
		}
	}
	return nil
}

// BufShim treats every call to [bufShim.MarshalJSON] as a [bufio.Scanner.Scan]
// call.
//
// Note this type is very weird, in that it can only be used for _either_ an
// Unmarshal or a Marshal, not both. Doing both on the same structure will
// silently do the wrong thing.
type bufShim struct {
	s   *bufio.Scanner
	buf []byte
}

func newBufShim(r io.Reader) *bufShim {
	s := new(bufShim)
	s.s = bufio.NewScanner(r)
	s.buf = getBuf()
	s.s.Buffer(s.buf, len(s.buf))
	return s
}

func (s *bufShim) MarshalJSON() ([]byte, error) {
	if !s.s.Scan() {
		return nil, s.s.Err()
	}
	return s.s.Bytes(), nil
}

func (s *bufShim) UnmarshalJSON(b []byte) error {
	s.buf = append(s.buf[0:0], b...)
	return nil
}

func (s *bufShim) Close() error {
	putBuf(s.buf)
	return nil
}

// Entry is a record of all information needed to record a vulnerability at a
// later date.
type Entry struct {
	CommonEntry
	Vuln       []*claircore.Vulnerability
	Enrichment []driver.EnrichmentRecord

	// These are hacks to prevent excessive memory consumption.
	vulns        *os.File
	vulnCt       int
	enrichments  *os.File
	enrichmentCt int
}

// CommonEntry is an embedded type that's shared between the "normal" [Entry] type
// and the on-disk JSON produced by the [Store.Store] method.
type CommonEntry struct {
	Updater     string
	Fingerprint driver.Fingerprint
	Date        time.Time
}

// DiskEntry is a single vulnerability or enrichment. It's made from unpacking an
// Entry's slice and adding an uuid for grouping back into an Entry upon read.
//
// "Vuln" and "Enrichment" are populated from the backing disk immediately
// before being serialized.
type diskEntry struct {
	CommonEntry
	Ref        uuid.UUID
	Vuln       *bufShim `json:",omitempty"`
	Enrichment *bufShim `json:",omitempty"`
	Kind       driver.UpdateKind
}

// Entries returns a map containing all the Entries stored by calls to
// UpdateVulnerabilities.
//
// It is unsafe for modification because it does not return a copy of the map.
func (s *Store) Entries() map[uuid.UUID]*Entry {
	s.RLock()
	defer s.RUnlock()
	return s.entry
}

// UpdateVulnerabilities records all provided vulnerabilities.
func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	now := time.Now()
	buf, err := diskBuf(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	for _, v := range vulns {
		if err := enc.Encode(v); err != nil {
			return uuid.Nil, err
		}
	}
	if _, err := buf.Seek(0, io.SeekStart); err != nil {
		return uuid.Nil, err
	}

	e := Entry{
		Vuln:   vulns,
		vulns:  buf,
		vulnCt: len(vulns),
	}
	e.Date = now
	e.Updater = updater
	e.Fingerprint = fingerprint
	ref := uuid.New()
	s.Lock()
	defer s.Unlock()
	for {
		if _, exist := s.entry[ref]; !exist {
			break
		}
		ref = uuid.New()
	}
	s.entry[ref] = &e
	s.latest[driver.VulnerabilityKind] = ref
	s.ops[updater] = append([]driver.UpdateOperation{{
		Ref:         ref,
		Date:        now,
		Fingerprint: fingerprint,
		Updater:     updater,
		Kind:        driver.VulnerabilityKind,
	}}, s.ops[updater]...)
	return ref, nil
}

// Copyops assumes all locks are taken care of.
func (s *Store) copyops(ty driver.UpdateKind, us ...string) map[string][]driver.UpdateOperation {
	ns := make(map[string]struct{})
	for _, n := range us {
		ns[n] = struct{}{}
	}
	m := make(map[string][]driver.UpdateOperation, len(s.ops))
	for k, v := range s.ops {
		// If we were passed a set of names and this wasn't in it, pass.
		// If we weren't passed a set of names, do the copy for everything.
		if _, ok := ns[k]; len(ns) != 0 && !ok {
			continue
		}
		n := make([]driver.UpdateOperation, len(v))
		copy(n, v)
		// Filter our copy by type, in place.
		i := 0
		for _, op := range n {
			if op.Kind == ty {
				n[i] = op
				i++
			}
		}
		n = n[:i]
		sort.Slice(n, func(i, j int) bool { return n[i].Date.Before(n[j].Date) })
		m[k] = n
	}
	return m
}

// GetUpdateOperations returns a list of UpdateOperations in date descending
// order for the given updaters.
//
// The returned map is keyed by Updater implementation's unique names.
//
// If no updaters are specified, all UpdateOperations are returned.
func (s *Store) GetUpdateOperations(_ context.Context, k driver.UpdateKind, us ...string) (map[string][]driver.UpdateOperation, error) {
	s.RLock()
	defer s.RUnlock()
	return s.copyops(k, us...), nil
}

// GetLatestUpdateRefs reports the latest update reference for every known
// updater.
func (s *Store) GetLatestUpdateRefs(_ context.Context, k driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
	s.RLock()
	defer s.RUnlock()
	return s.copyops(k), nil
}

// GetLatestUpdateRef reports the latest update reference of any known
// updater.
func (s *Store) GetLatestUpdateRef(_ context.Context, k driver.UpdateKind) (uuid.UUID, error) {
	s.RLock()
	defer s.RUnlock()
	return s.latest[k], nil
}

// DeleteUpdateOperations is unimplemented.
func (s *Store) DeleteUpdateOperations(context.Context, ...uuid.UUID) (int64, error) {
	return 0, nil
}

// GetUpdateDiff is unimplemented.
func (s *Store) GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return nil, nil
}

// Initialized implements vulnstore.Updater.
func (s *Store) Initialized(context.Context) (bool, error) {
	s.RLock()
	defer s.RUnlock()
	return len(s.entry) != 0, nil
}

// GC is unimplemented.
func (s *Store) GC(_ context.Context, _ int) (int64, error) {
	return 0, nil
}

// UpdateEnrichments creates a new EnrichmentUpdateOperation, inserts the provided
// EnrichmentRecord(s), and ensures enrichments from previous updates are not
// queries by clients.
func (s *Store) UpdateEnrichments(ctx context.Context, kind string, fp driver.Fingerprint, es []driver.EnrichmentRecord) (uuid.UUID, error) {
	now := time.Now()
	buf, err := diskBuf(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	for _, v := range es {
		if err := enc.Encode(v); err != nil {
			return uuid.Nil, err
		}
	}
	if _, err := buf.Seek(0, io.SeekStart); err != nil {
		return uuid.Nil, err
	}

	e := Entry{
		Enrichment:   es,
		enrichments:  buf,
		enrichmentCt: len(es),
	}
	e.Date = now
	e.Updater = kind
	e.Fingerprint = fp
	ref := uuid.New()
	s.Lock()
	defer s.Unlock()
	for {
		if _, exist := s.entry[ref]; !exist {
			break
		}
		ref = uuid.New()
	}
	s.latest[driver.EnrichmentKind] = ref
	s.entry[ref] = &e
	s.ops[kind] = append([]driver.UpdateOperation{{
		Ref:         ref,
		Date:        now,
		Fingerprint: fp,
		Updater:     kind,
		Kind:        driver.EnrichmentKind,
	}}, s.ops[kind]...)
	return ref, nil
}

// RecordUpdaterStatus is unimplemented.
func (s *Store) RecordUpdaterStatus(ctx context.Context, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) error {
	return nil
}

// RecordUpdaterSetStatus is unimplemented.
func (s *Store) RecordUpdaterSetStatus(ctx context.Context, updaterSet string, updateTime time.Time) error {
	return nil
}

// DeltaUpdateVulnerabilities just calls UpdateVulnerabilities. In the jsonblob flow it is assumed that
// we're always starting from zero.
// Note: deleted is ignored.
func (s *Store) DeltaUpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability, deleted []string) (uuid.UUID, error) {
	return s.UpdateVulnerabilities(ctx, updater, fingerprint, vulns)
}

// UpdateEnrichmentsIter is unimplemented.
func (s *Store) UpdateEnrichmentsIter(_ context.Context, _ string, _ driver.Fingerprint, _ datastore.EnrichmentIter) (uuid.UUID, error) {
	return uuid.Nil, errors.ErrUnsupported
}

// UpdateVulnerabilitiesIter is unimplemented.
func (s *Store) UpdateVulnerabilitiesIter(_ context.Context, _ string, _ driver.Fingerprint, _ datastore.VulnerabilityIter) (uuid.UUID, error) {
	return uuid.Nil, errors.ErrUnsupported
}

var bufPool sync.Pool

func getBuf() []byte {
	const sz = 1 << 20 // 1MiB
	b, ok := bufPool.Get().([]byte)
	if !ok {
		b = make([]byte, sz)
	}
	return b
}
func putBuf(b []byte) {
	bufPool.Put(b)
}
