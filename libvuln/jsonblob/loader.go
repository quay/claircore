package jsonblob

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

// NewLoader creates a new Loader from the provided [io.Reader].
func NewLoader(r io.Reader) (*Loader, error) {
	l := Loader{
		dec: json.NewDecoder(r),
		cur: uuid.Nil,
	}
	return &l, nil
}

// Loader is an iterator that returns a series of [Entry].
//
// Users should call [*Loader.Next] until it reports false, then check for
// errors via [*Loader.Err].
type Loader struct {
	err error
	e   *Entry

	dec  *json.Decoder
	next *Entry
	de   diskEntry
	cur  uuid.UUID
}

// Next reports whether there's an [Entry] to be processed.
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
		switch l.de.Kind {
		case driver.VulnerabilityKind:
			vuln := claircore.Vulnerability{}
			if err := json.Unmarshal(l.de.Vuln.buf, &vuln); err != nil {
				l.err = err
				return false
			}
			l.next.Vuln = append(l.next.Vuln, &vuln)
		case driver.EnrichmentKind:
			en := driver.EnrichmentRecord{}
			if err := json.Unmarshal(l.de.Enrichment.buf, &en); err != nil {
				l.err = err
				return false
			}
			l.next.Enrichment = append(l.next.Enrichment, en)
		}
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

// Entry returns the latest loaded [Entry].
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
