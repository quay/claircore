package oracle

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	ovalhelper "github.com/quay/claircore/pkg/oval"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"
)

var _ driver.Parser = (*Updater)(nil)

// Parse implements driver.Parser.
func (u *Updater) Parse(r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx := u.logger.WithContext(context.Background())
	// In tests, this takes at least 140 seconds. So, round up on the automatic
	// timeout.
	ctx, done := context.WithTimeout(ctx, 5*time.Minute)
	defer done()
	return u.ParseContext(ctx, r)
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
		d.Name = "Oracle Linux"
		d.Version = fmt.Sprintf("%s %s", d.Name, d.VersionID)
		m[v] = d
	}
	return d
}

// ParseContext is like Parse, but with context.
func (u *Updater) ParseContext(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().Str("component", u.Name()).Logger()
	log.Info().Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("oracle: unable to decode OVAL document: %w", err)
	}
	log.Debug().Msg("xml decoded")

	db := &db{
		root:    &root,
		distMap: newDistMap(),
	}
	vs := make([]*claircore.Vulnerability, 0, len(root.Definitions.Definitions))

	for i, def := range root.Definitions.Definitions {
		if i != 0 && i%1000 == 0 {
			log.Debug().Msgf("processed %d definitions", i)
		}
		// It's likely that we'll have multiple vulnerabilites spawned from once
		// CVE/definition, so this constructs new records on demand.
		mkVuln := func() *claircore.Vulnerability {
			return &claircore.Vulnerability{
				Updater:     u.Name(),
				Name:        def.References[0].RefID,
				Description: strings.TrimSpace(def.Description),
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
			v, err := db.populate(ctx, mkVuln(), crit)
			if err != nil {
				return nil, err
			}
			if v.Package.Name != "" {
				vs = append(vs, v)
			}
		}
	}

	log.Info().Msgf("found %d vulnerabilities in %d definitions", len(vs), len(root.Definitions.Definitions))
	return vs, nil
}

type db struct {
	root    *oval.Root
	distMap distMap
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
			return fmt.Errorf("oracle: walking oval definition: unknown operator %q", cur.Operator)
		}
		return nil
	}

	return out, fn(testRefs, root)
}

func (db *db) populate(_ context.Context, v *claircore.Vulnerability, crit []*oval.Criterion) (*claircore.Vulnerability, error) {
	var rt *oval.RPMInfoTest
	var obj *oval.RPMInfoObject
	var state *oval.RPMInfoState

	for _, c := range crit {
		// First, resolve our test.
		k, i, err := db.root.Tests.Lookup(c.TestRef)
		if err != nil {
			return nil, fmt.Errorf("oracle: dangling ref: %w", err)
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
			return nil, fmt.Errorf("oracle: dangling ref: %w", err)
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
		case obj.Name == "oraclelinux-release":
			var state *oval.RPMInfoState
			for _, sr := range rt.StateRefs {
				k, i, err := db.root.States.Lookup(sr.StateRef)
				if err != nil {
					return nil, fmt.Errorf("oracle: dangling ref: %w", err)
				}
				if k != "rpminfo_state" {
					// ???
					continue
				}
				state = &db.root.States.RPMInfoStates[i]
				var ver int
				switch {
				case state.RPMVersion != nil:
					if _, err := fmt.Sscanf(state.RPMVersion.Body, `^%d`, &ver); err != nil {
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
				return nil, fmt.Errorf("oracle: dangling ref: %w", err)
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
