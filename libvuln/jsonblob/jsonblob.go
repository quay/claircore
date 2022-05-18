package jsonblob

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
type Store struct {
	sync.RWMutex
	entry  map[uuid.UUID]*Entry
	ops    map[string][]driver.UpdateOperation
	latest map[driver.UpdateKind]uuid.UUID
}

// Load reads in all the records serialized in the provided Reader.
func Load(ctx context.Context, r io.Reader) (*Loader, error) {
	l := Loader{
		dec: json.NewDecoder(r),
		cur: uuid.Nil,
	}
	return &l, nil
}

// Loader is an iterator struct that returns Entries.
//
// Users should call Next until it reports false, then check for errors via Err.
type Loader struct {
	err error
	e   *Entry

	dec  *json.Decoder
	next *Entry
	de   diskEntry
	cur  uuid.UUID
}

// Next reports whether there's a Entry to be processed.
func (l *Loader) Next() bool {
	if l.err != nil {
		return false
	}

	for l.err = l.dec.Decode(&l.de); l.err == nil; l.err = l.dec.Decode(&l.de) {
		id := l.de.Ref
		// If we just hit a new Entry, promote the current one.
		if id != l.cur {
			l.e = l.next
			l.next = &Entry{}
			l.next.Updater = l.de.Updater
			l.next.Fingerprint = l.de.Fingerprint
			l.next.Date = l.de.Date
		}
		l.next.Vuln = append(l.next.Vuln, l.de.Vuln)
		l.de.Vuln = nil // Needed to ensure the Decoder allocates new backing memory.

		// If this was an initial diskEntry, promote the ref.
		if id != l.cur {
			l.cur = id
			// If we have an Entry ready, report that.
			if l.e != nil {
				return true
			}
		}
	}
	l.e = l.next
	return true
}

// Entry returns the latest loaded Entry.
func (l *Loader) Entry() *Entry {
	return l.e
}

// Err is the latest encountered error.
func (l *Loader) Err() error {
	// Don't report EOF as an error.
	if errors.Is(l.err, io.EOF) {
		return nil
	}
	return l.err
}

// Store writes out the Store to the provided Writer. It's the inverse of Load.
func (s *Store) Store(w io.Writer) error {
	s.RLock()
	defer s.RUnlock()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for id, e := range s.entry {
		for _, v := range e.Vuln {
			if err := enc.Encode(&diskEntry{
				CommonEntry: e.CommonEntry,
				Ref:         id,
				Vuln:        v,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Entry is a record of all information needed to record a vulnerability at a
// later date.
type Entry struct {
	CommonEntry
	Vuln       []*claircore.Vulnerability
	Enrichment []driver.EnrichmentRecord
}

// CommonEntry is an embedded type that's shared between the "normal" Entry type
// and the on-disk json produced by a Store's Load method.
type CommonEntry struct {
	Updater     string
	Fingerprint driver.Fingerprint
	Date        time.Time
}

// DiskEntry is a single vulnerability. It's made from unpacking an Entry's
// slice and adding a uuid for grouping back into an Entry upon read.
type diskEntry struct {
	CommonEntry
	Ref        uuid.UUID
	Vuln       *claircore.Vulnerability
	Enrichment *driver.EnrichmentRecord
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
func (s *Store) UpdateVulnerabilities(_ context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	now := time.Now()
	e := Entry{
		Vuln: vulns,
	}
	e.Date = now
	e.Updater = updater
	e.Fingerprint = fingerprint
	ref := uuid.New() // God help you if this wasn't unique.
	s.Lock()
	defer s.Unlock()
	s.latest[driver.VulnerabilityKind] = ref
	s.entry[ref] = &e
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
	e := Entry{
		Enrichment: es,
	}
	e.Date = now
	e.Updater = kind
	e.Fingerprint = fp
	ref := uuid.New() // God help you if this wasn't unique.
	s.Lock()
	defer s.Unlock()
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
