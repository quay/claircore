// Package pep440 implements types for working with versions as defined in
// PEP-440.
package pep440

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/quay/claircore"
)

var pattern *regexp.Regexp

func init() {
	// This is the regexp used in the "versioning" package, as noted in
	// https://www.python.org/dev/peps/pep-0440/#id81
	const r = `v?` +
		`(?:` +
		`(?:(?P<epoch>[0-9]+)!)?` + // epoch
		`(?P<release>[0-9]+(?:\.[0-9]+)*)` + // release segment
		`(?P<pre>[-_\.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?P<pre_n>[0-9]+)?)?` + // pre release
		`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?` + // post release
		`(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?` + // dev release
		`)` +
		`(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?` // local version
	pattern = regexp.MustCompile(r)
}

// Version repesents a canonical-ish represention of a PEP440 version.
//
// Local revisions are discarded.
type Version struct {
	Epoch   int
	Release []int
	Pre     struct {
		Label string
		N     int
	}
	Post int
	Dev  int
}

// Version returns a fixed-width slice of integers meant for allowing some
// amount of version comparision with no knowledge of the version scheme.
//
// In generating this slice, the following rules are applied:
//
// Release is normalized to five numbers. Missing numbers are set to "0" and
// additional numbers are dropped.
//
// The Dev revision is promoted earlier in the int slice if there's no Pre or
// Post revision, and sorts as earlier than a Pre revision.
func (v *Version) Version() (c claircore.Version) {
	const (
		epoch = 0
		rel   = 1
		preL  = 6
		preN  = 7
		post  = 8
		dev   = 9
	)
	// BUG(hank) The int-slice versioning method tries to accomdate arbitrary
	// numbers, but may give odd results with sufficiently large revision
	// numbers. One suggested workaround is to make fewer than 9 quintillion
	// releases.
	c.Kind = "pep440"
	c.V[epoch] = int32(v.Epoch)
	for i, n := range v.Release {
		if i > 4 {
			break
		}
		c.V[rel+i] = int32(n)
	}
	switch v.Pre.Label {
	case "a":
		c.V[preL] = -3
	case "b":
		c.V[preL] = -2
	case "rc":
		c.V[preL] = -1
	}
	c.V[preN] = int32(v.Pre.N)
	c.V[post] = int32(v.Post)
	if v.Dev != 0 {
		if v.Post != 0 || c.V[preL] != 0 {
			c.V[dev] = -int32(v.Dev)
		} else {
			const minInt = -int32((^uint32(0))>>1) - 1
			c.V[preL] = minInt + int32(v.Dev)
		}
	}

	return c
}

// String returns the canonicalized representation of the Version.
func (v *Version) String() string {
	var b strings.Builder
	if v.Epoch != 0 {
		fmt.Fprintf(&b, "%d!", v.Epoch)
	}
	for i, n := range v.Release {
		if i != 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatInt(int64(n), 10))
	}
	if v.Pre.Label != "" {
		b.WriteString(v.Pre.Label)
		b.WriteString(strconv.FormatInt(int64(v.Pre.N), 10))
	}
	if v.Post != 0 {
		fmt.Fprintf(&b, ".post%d", v.Post)
	}
	if v.Dev != 0 {
		fmt.Fprintf(&b, ".dev%d", v.Dev)
	}
	return b.String()
}

// Compare returns an integer comparing two versions. The result will be 0 if
// a == b, -1 if a < b and +1 if a > b.
func (a *Version) Compare(b *Version) int {
	av, bv := a.Version(), b.Version()
	return av.Compare(&bv)
}

// Parse attempts to extract a PEP-440 version string from the provided string.
func Parse(s string) (v Version, err error) {
	if !pattern.MatchString(s) {
		return v, fmt.Errorf("invalid pep440 version: %q", s)
	}

	ms := pattern.FindStringSubmatch(s)
	for i, n := range pattern.SubexpNames() {
		if ms[i] == "" {
			continue
		}

		switch n {
		case "epoch":
			v.Epoch, err = strconv.Atoi(ms[i])
			if err != nil {
				return v, err
			}
		case "release":
			ns := strings.Split(ms[i], ".")
			v.Release = make([]int, len(ns))
			for i, n := range ns {
				v.Release[i], err = strconv.Atoi(n)
				if err != nil {
					return v, err
				}
			}
		case "pre_l":
			switch l := ms[i]; l {
			case "a", "alpha":
				v.Pre.Label = "a"
			case "b", "beta":
				v.Pre.Label = "b"
			case "rc", "c", "pre", "preview":
				v.Pre.Label = "rc"
			default:
				return v, fmt.Errorf("unknown pre-release label %q", l)
			}
		case "pre_n":
			v.Pre.N, err = strconv.Atoi(ms[i])
			if err != nil {
				return v, err
			}
		case "post_n1", "post_n2":
			v.Post, err = strconv.Atoi(ms[i])
			if err != nil {
				return v, err
			}
		case "dev_n":
			v.Dev, err = strconv.Atoi(ms[i])
			if err != nil {
				return v, err
			}
		}
	}

	return v, nil
}

// Versions implements sort.Interface.
type Versions []Version

func (vs Versions) Len() int {
	return len([]Version(vs))
}

func (vs Versions) Less(i, j int) bool {
	return vs[i].Compare(&vs[j]) == -1
}

func (vs Versions) Swap(i, j int) {
	vs[i], vs[j] = vs[j], vs[i]
}
