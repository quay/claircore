package rhel // import "github.com/quay/claircore/rhel"

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	ovalhelper "github.com/quay/claircore/pkg/oval"
	"github.com/quay/claircore/pkg/tmp"

	"github.com/quay/goval-parser/oval"
)

// We currently grab the oval databases db distro-wise.
const dbURL = `https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL%d.xml`

var _ driver.Updater = (*Updater)(nil)
var _ driver.FetcherNG = (*Updater)(nil)

// Updater fetches and parses RHEL-flavored OVAL databases.
type Updater struct {
	client  *http.Client
	version int
	dbURL   string
}

type Release int

const (
	RHEL3 Release = 3
	RHEL4 Release = 4
	RHEL5 Release = 5
	RHEL6 Release = 6
	RHEL7 Release = 7
	RHEL8 Release = 8
)

// NewUpdater returns an Updater.
func NewUpdater(v Release, opt ...Option) (*Updater, error) {
	u := &Updater{
		version: int(v),
		dbURL:   fmt.Sprintf(dbURL, v),
	}
	for _, f := range opt {
		if err := f(u); err != nil {
			return nil, err
		}
	}
	if u.client == nil {
		u.client = http.DefaultClient
	}
	return u, nil
}

// Option is a type to configure an Updater.
type Option func(*Updater) error

// WithURL overrides the guessed URL for the OVAL database.
func WithURL(url string) Option {
	return func(u *Updater) error {
		u.dbURL = url
		return nil
	}
}

// WithClient sets an http.Client for use with an Updater.
//
// If this Option is not supplied, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(u *Updater) error {
		u.client = c
		return nil
	}
}

// Name satisifies the driver.Updater interface.
func (u *Updater) Name() string {
	return fmt.Sprintf("rhel-%d-updater", u.version)
}

// Fetch satisifies the driver.Updater interface.
func (u *Updater) Fetch() (io.ReadCloser, string, error) {
	ctx, done := context.WithTimeout(context.Background(), time.Minute)
	defer done()
	rc, hint, err := u.FetchContext(ctx, "")
	if err != nil {
		return nil, "", err
	}
	return rc, string(hint), nil
}

// FetchContext is like Fetch, but with context.
func (u *Updater) FetchContext(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.dbURL, nil)
	if err != nil {
		return nil, hint, err
	}
	if hint != "" {
		req.Header.Set("If-Modified-Since", string(hint))
	}

	tf, err := tmp.NewFile("", u.Name()+".")
	if err != nil {
		return nil, hint, err
	}

	res, err := u.client.Do(req)
	if err != nil {
		return nil, hint, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		tf.Close()
		return nil, hint, driver.Unchanged
	case http.StatusOK:
		// break
	default:
		return nil, hint, fmt.Errorf("rhel: fetcher got unexpected HTTP response: %d (%s)", res.StatusCode, res.Status)
	}

	if _, err := io.Copy(tf, res.Body); err != nil {
		tf.Close()
		return nil, hint, err
	}
	if o, err := tf.Seek(0, io.SeekStart); err != nil || o != 0 {
		tf.Close()
		return nil, hint, err
	}

	if t := res.Header.Get("Last-Modified"); t != "" {
		hint = driver.Fingerprint(t)
	}
	return tf, hint, nil
}

// Parse satisifies the driver.Updater interface.
func (u *Updater) Parse(r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	return u.ParseContext(context.Background(), r)
}

// DistMap is a helper to prevent making thousands of Distribution objects.
type distMap map[int]*claircore.Distribution

func newDistMap() distMap {
	return distMap(make(map[int]*claircore.Distribution))
}
func (m distMap) Version(v int) *claircore.Distribution {
	d, ok := m[v]
	if !ok {
		d = &claircore.Distribution{}
		d.VersionID = strconv.Itoa(v)
		d.Name = "Red Hat Enterprise Linux"
		d.Version = fmt.Sprintf("%s %s", d.Name, d.VersionID)
		m[v] = d
	}
	return d
}

// ParseContext is like Parse, but with context.
func (u *Updater) ParseContext(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("rhel: unable to decode OVAL document: %w", err)
	}

	db := &db{
		root:    &root,
		distMap: newDistMap(),
	}
	vs := make([]*claircore.Vulnerability, 0, len(root.Definitions.Definitions))

	for _, def := range root.Definitions.Definitions {
		// It's likely that we'll have multiple vulnerabilites spawned from once
		// CVE/definition, so this constructs new records on demand.
		db.mkVuln = func() *claircore.Vulnerability {
			return &claircore.Vulnerability{
				Updater:     u.Name(),
				Name:        def.References[0].RefID,
				Description: def.Description,
				Severity:    def.Advisory.Severity,
				Links:       ovalhelper.Links(def),
				Package:     &claircore.Package{},
			}
		}

		crit, err := walk(&def.Criteria)
		if err != nil {
			return nil, err
		}

		for _, crit := range crit {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			v, err := db.populate(ctx, crit)
			if err != nil {
				return nil, err
			}
			if v.Package.Name != "" {
				vs = append(vs, v)
			}
		}
	}

	return vs, nil
}

type db struct {
	root    *oval.Root
	distMap distMap
	mkVuln  func() *claircore.Vulnerability
}

// Walk returns a slice of slices of Criterions that should be AND'd together to
// determine if a package is vulnerable.
func walk(root *oval.Criteria) ([][]*oval.Criterion, error) {
	out := make([][]*oval.Criterion, 0)
	testRefs := []*oval.Criterion{}
	var fn func([]*oval.Criterion, *oval.Criteria) error
	fn = func(stack []*oval.Criterion, cur *oval.Criteria) error {
		switch cur.Operator {
		case "AND":
			for i := range cur.Criterions {
				c := &cur.Criterions[i]
				stack = append(stack, c)
			}
			if len(cur.Criterias) == 0 {
				// the current node's Criterions are leaves
				r := make([]*oval.Criterion, len(stack))
				copy(r, stack)
				out = append(out, r)
			}
			for _, c := range cur.Criterias {
				if err := fn(stack, &c); err != nil {
					return err
				}
			}
		case "OR":
			// TODO(hank) See if it's valid to have an OR node with criterions
			// and criterias.
			if len(cur.Criterions) == 0 {
				for _, c := range cur.Criterias {
					if err := fn(stack, &c); err != nil {
						return err
					}
				}
			}
			for i := range cur.Criterions {
				c := &cur.Criterions[i]
				stack = append(stack, c)
				for _, c := range cur.Criterias {
					if err := fn(stack, &c); err != nil {
						return err
					}
				}
			}
		default:
			return fmt.Errorf("rhel: walking oval definition: unknown operator %q", cur.Operator)
		}
		return nil
	}

	return out, fn(testRefs, root)
}

func (db *db) populate(_ context.Context, crit []*oval.Criterion) (*claircore.Vulnerability, error) {
	v := db.mkVuln()
	var rt *oval.RPMInfoTest
	var obj *oval.RPMInfoObject
	var state *oval.RPMInfoState

	for _, c := range crit {
		// First, resolve our test.
		k, i, err := db.root.Tests.Lookup(c.TestRef)
		if err != nil {
			return nil, fmt.Errorf("rhel: dangling ref: %w", err)
		}
		if k != "rpminfo_test" {
			continue
		}
		rt = &db.root.Tests.RPMInfoTests[i]
		if len(rt.ObjectRefs) != 1 {
			return nil, fmt.Errorf("unsure how to handle multple object references in a test")
		}

		// Then, resolve the object the test is referencing.
		objRef := rt.ObjectRefs[0].ObjectRef
		k, objidx, err := db.root.Objects.Lookup(objRef)
		if err != nil {
			return nil, fmt.Errorf("rhel: dangling ref: %w", err)
		}
		if k != "rpminfo_object" {
			continue
		}
		obj = &db.root.Objects.RPMInfoObjects[objidx]

		//  If the object is "redhat-release", special case it to pull out
		//  distro version information, and associte that with the current
		//  package.
		switch {
		case obj == nil:
			return nil, fmt.Errorf("unable to lookup ref %q (probably programmer error)", objRef)
		case obj.Name == "redhat-release":
			var state *oval.RPMInfoState
			for _, sr := range rt.StateRefs {
				k, i, err := db.root.States.Lookup(sr.StateRef)
				if err != nil {
					return nil, fmt.Errorf("rhel: dangling ref: %w", err)
				}
				if k != "rpminfo_state" {
					// ???
					continue
				}
				state = &db.root.States.RPMInfoStates[i]
				var ver int
				switch {
				case state.RPMVersion != nil:
					if _, err := fmt.Sscanf(state.RPMVersion.Body, `^%d[^\d]`, &ver); err != nil {
						return nil, err
					}
				case state.EVR != nil:
					if _, err := fmt.Sscanf(state.EVR.Body, `0:%d`, &ver); err != nil {
						return nil, err
					}
				}
				v.Package.Dist = db.distMap.Version(ver)
			}
			continue
		default:
		}

		// Otherwise, resolve the states referenced in the tests and populate
		// the package struct in this vulnerability
		for _, sr := range rt.StateRefs {
			k, i, err := db.root.States.Lookup(sr.StateRef)
			if err != nil {
				return nil, fmt.Errorf("rhel: dangling ref: %w", err)
			}
			if k != "rpminfo_state" { // ???
				continue
			}
			state = &db.root.States.RPMInfoStates[i]

			switch {
			case state.SignatureKeyID != nil:
				// Skip checking the signing key ID for now. Later we
				// should use this to associate the package with a
				// repository.
				continue
			case state.EVR != nil:
				v.Package.Name = obj.Name
				v.Package.Version = state.EVR.Body
				v.Package.NameVersion = fmt.Sprintf("%s %s", v.Package.Name, v.Package.Version)
				v.Package.Kind = "binary"
			case state.Arch != nil:
				// ???
			}
		}
	}

	return v, nil
}
