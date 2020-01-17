package ovalutil

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
)

// RPMInfo holds information for extracting Vulnerabilities from an OVAL
// database with rpm_info states, objects, and tests.
type RPMInfo struct {
	root  *oval.Root
	dists map[string]*claircore.Distribution
}

// NewRPMInfo creates an RPMInfo ready to examine the passed-in OVAL database.
func NewRPMInfo(root *oval.Root) *RPMInfo {
	return &RPMInfo{
		root:  root,
		dists: make(map[string]*claircore.Distribution),
	}
}

// Platexp is an attempt to pull a name and version from the OVAL
// definition>afftected>platform node.
var platexp = regexp.MustCompile(`(?P<name>.+) (?P<version>[0-9]+)(?P<suse> (SP[0-9]+) for .+)?`)

// Dist returns a Distribution from the provided string and memoizes the result.
func (r *RPMInfo) dist(v string) *claircore.Distribution {
	d, ok := r.dists[v]
	if !ok {
		d = &claircore.Distribution{}
		match := platexp.FindStringSubmatch(v)
		d.VersionID = match[2]
		if match[3] != "" {
			d.VersionID = d.VersionID + " " + match[4]
		}
		d.Name = match[1]
		d.Version = fmt.Sprintf("%s %s", d.Name, d.VersionID)
		d.PrettyName = d.Version // RHEL hack. See also: ../../osrelease/scanner.go:/BUGZILLA
		r.dists[v] = d
	}
	return d
}

// Extract pulls out all Vulnerabilites by walking all the definition's criteria
// and pulling out rpm_info objects that have rpm_info evr tests.
func (r *RPMInfo) Extract(ctx context.Context) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "pkg/ovalutil/RPMInfo.Extract").
		Logger()
	ctx = log.WithContext(ctx)
	defs := r.root.Definitions.Definitions
	vs := make([]*claircore.Vulnerability, 0, len(defs))

	for _, def := range defs {
		var dist *claircore.Distribution
	Affecteds:
		for _, a := range def.Affecteds {
			if a.Family != "unix" {
				continue
			}
			for _, p := range a.Platforms {
				if d := r.dist(p); d != nil {
					dist = d
					break Affecteds
				}
			}
		}
		if dist == nil {
			panic("that's weird")
		}
		// TODO(hank) There should be a one-to-many mapping of vulnerability to
		// CPE.
		if cpes := def.Advisory.AffectedCPEList; len(cpes) != 0 {
			for _, v := range cpes {
				var err error
				var wfn common.WellFormedName
				switch {
				case common.ValidateURI(v) == nil:
					wfn, err = naming.UnbindURI(v)
				case common.ValidateFS(v) == nil:
					wfn, err = naming.UnbindFS(v)
				}
				switch {
				case err != nil:
				case wfn.GetString("part") == "o":
					dist.CPE = naming.BindToURI(wfn)
				}
			}
		}
		// It's likely that we'll have multiple vulnerabilites spawned from once
		// CVE/definition, so this constructs new records on demand.
		links := Links(def)
		mkVuln := func() *claircore.Vulnerability {
			return &claircore.Vulnerability{
				Name:        def.References[0].RefID,
				Description: strings.TrimSpace(def.Description),
				Severity:    def.Advisory.Severity,
				Links:       links,
				Dist:        dist,
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
			v, err := r.populate(ctx, mkVuln(), crit)
			if err != nil {
				return nil, err
			}
			vs = append(vs, v)
		}
	}

	log.Info().
		Int("vulnerabilities", len(vs)).
		Int("definitions", len(defs)).
		Msg("database processed")
	return vs, nil
}

// Walk returns a slice of slices of Criterions that should be AND'd together to
// determine if a package is vulnerable.
func walk(root *oval.Criteria) ([][]*oval.Criterion, error) {
	out := make([][]*oval.Criterion, 0)
	if root.Criterias == nil && root.Criterions == nil {
		// SUSE seems to just jam CVEs into the feed of the older products,
		// without bothing to connect them to packages.
		return out, nil
	}
	// This is the stack we use for the tree walk. It should never get so deep
	// that it needs to be grown.
	workstack := make([]*oval.Criterion, 0, 8)
	var fn func([]*oval.Criterion, *oval.Criteria) error
	fn = func(stack []*oval.Criterion, cur *oval.Criteria) error {
		switch cur.Operator {
		case "AND":
			// Push all of our AND'd nodes onto the stack.
			for i := range cur.Criterions {
				c := &cur.Criterions[i]
				stack = append(stack, c)
			}
			switch len(cur.Criterias) {
			case 0: // the current node's Criterions are leaves
				r := make([]*oval.Criterion, len(stack))
				copy(r, stack)
				out = append(out, r)
			default:
				for _, c := range cur.Criterias {
					if err := fn(stack, &c); err != nil {
						return err
					}
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
			// Usual case:
			for i := range cur.Criterions {
				c := &cur.Criterions[i]
				// Make sure to only use this for this iteration.
				stack := append(stack, c)
				switch len(cur.Criterias) {
				case 0:
					// the current node's Criterions are leaves
					r := make([]*oval.Criterion, len(stack))
					copy(r, stack)
					out = append(out, r)
				default:
					for _, c := range cur.Criterias {
						if err := fn(stack, &c); err != nil {
							return err
						}
					}
				}
			}
		default:
			return fmt.Errorf("ovalutil: walking oval definition: unknown operator %q", cur.Operator)
		}
		return nil
	}

	return out, fn(workstack, root)
}

func (r *RPMInfo) populate(ctx context.Context, v *claircore.Vulnerability, crit []*oval.Criterion) (*claircore.Vulnerability, error) {
	var rt *oval.RPMInfoTest
	var obj *oval.RPMInfoObject
	var state *oval.RPMInfoState

	for _, c := range crit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// First, resolve our test.
		k, i, err := r.root.Tests.Lookup(c.TestRef)
		if err != nil {
			return nil, fmt.Errorf("ovalutil: dangling ref: %w", err)
		}
		if k != "rpminfo_test" {
			continue
		}
		rt = &r.root.Tests.RPMInfoTests[i]
		if len(rt.ObjectRefs) != 1 {
			return nil, fmt.Errorf("unsure how to handle multple object references in a test")
		}

		// Then, resolve the object the test is referencing.
		objRef := rt.ObjectRefs[0].ObjectRef
		k, objidx, err := r.root.Objects.Lookup(objRef)
		if err != nil {
			return nil, fmt.Errorf("ovalutil: dangling ref: %w", err)
		}
		if k != "rpminfo_object" {
			continue
		}
		obj = &r.root.Objects.RPMInfoObjects[objidx]
		if obj == nil {
			return nil, fmt.Errorf("unable to lookup ref %q (probably programmer error)", objRef)
		}

		// Otherwise, resolve the states referenced in the tests and populate
		// the package struct in this vulnerability
		for _, sr := range rt.StateRefs {
			k, i, err := r.root.States.Lookup(sr.StateRef)
			if err != nil {
				return nil, fmt.Errorf("ovalutil: dangling ref: %w", err)
			}
			if k != "rpminfo_state" { // ???
				continue
			}
			state = &r.root.States.RPMInfoStates[i]

			switch {
			case state.SignatureKeyID != nil:
				// Skip checking the signing key ID for now. Later we
				// should use this to associate the package with a
				// repository.
				continue
			case state.EVR != nil:
				v.Package.Name = obj.Name
				v.Package.Kind = "binary"
				switch state.EVR.Operation {
				case oval.OpLessThan:
					v.FixedInVersion = state.EVR.Body
				case oval.OpLessThanOrEqual, oval.OpEquals:
					v.Package.Version = state.EVR.Body
				case oval.OpGreaterThan, oval.OpGreaterThanOrEqual: // ???
				}
			case state.Arch != nil:
				// ???
			}
		}
	}

	return v, nil
}
