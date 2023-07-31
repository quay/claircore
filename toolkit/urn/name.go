package urn

import (
	"net/url"
	"strings"
)

// Name is a claircore name.
//
// Names are expected to be unique within a claircore system and comparable
// across instances. Names are hierarchical, moving from least specific to most
// specific.
//
// Any pointer fields are optional metadata that may not exist depending on the
// (System, Kind) pair.
type Name struct {
	// System scopes to a claircore system or "mode", such as "indexer" or
	// "updater".
	System string
	// Kind scopes to a specific type of object used within the System.
	Kind string
	// Name scopes to a specific object within the system.
	Name string
	// Version is the named object's version.
	//
	// Versions can be ordered with a lexical sort.
	Version *string
}

// String implements fmt.Stringer.
func (n *Name) String() string {
	v := url.Values{}
	if n.Version != nil {
		v.Set("version", *n.Version)
	}
	u := URN{
		NID: `claircore`,
		NSS: strings.Join(
			[]string{n.System, n.Kind, n.Name},
			":",
		),
		q: v.Encode(),
	}

	return u.String()
}
