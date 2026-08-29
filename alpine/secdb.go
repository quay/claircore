package alpine

import (
	"strings"
	"unique"

	"github.com/quay/claircore"
)

// SecurityDB is the security database structure.
type SecurityDB struct {
	Distroversion string    `json:"distroversion"`
	Reponame      string    `json:"reponame"`
	Urlprefix     string    `json:"urlprefix"`
	Apkurl        string    `json:"apkurl"`
	Packages      []Package `json:"packages"`
}

// Package wraps the Details.
type Package struct {
	Pkg Details `json:"pkg"`
}

// Details define a package's name and relevant security fixes included in a
// given version.
type Details struct {
	Name string `json:"name"`
	// Fixed package version string mapped to an array of CVE ids affecting the
	// package.
	Secfixes map[string][]Flaw `json:"secfixes"`
}

// Flaw is a helper to create Aliases on demand.
type Flaw string

// Aliases constructs aliases for the Flaw.
//
// The "aka" alias may not be valid. The caller should check with
// [claircore.Alias.Valid].
func (f Flaw) Aliases() (self, aka claircore.Alias) {
	s := string(f)
	self.Space = space
	self.Name = s
	if space, name, ok := strings.Cut(s, `-`); ok {
		aka.Space = unique.Make(space)
		aka.Name = name
	}
	return
}

// String implements [fmt.Stringer].
func (f Flaw) String() string { return string(f) }
