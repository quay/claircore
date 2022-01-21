package driver

import (
	"context"

	"github.com/quay/claircore"
)

// An Ecosystem groups together scanners and a Coalescer which are commonly used
// together.
//
// A typical ecosystem is "dpkg" which will use the "dpkg" package indexer, the
// "os-release" distribution scanner and the "apt" repository scanner.
//
// A Controller will scan layers with all scanners present in its configured
// ecosystems.
type Ecosystem struct {
	Scanners  func(context.Context) ([]Scanner, error)
	Coalescer func(context.Context) (Coalescer, error)
	Name      string
}

// LayerDescription describes all the representable changes in a layer.
type LayerDescription struct {
	Digest       claircore.Digest
	Package      []LayerChange[claircore.Package]
	Distribution []LayerChange[claircore.Distribution]
	Repository   []LayerChange[claircore.Repository]
	Opaque       []LayerChange[Opaque]
}

// Opaque represents an opaque whiteout.
//
// See the OCI image spec for details.
type Opaque struct{}

// Coalescer takes a set of layers and creates coalesced IndexReport.
//
// A coalesced IndexReport should provide only the packages present in the
// final container image once all layers were applied.
type Coalescer interface {
	Coalesce(context.Context, []LayerDescription) (*claircore.IndexReport, error)
}

// BUG(hank) The Coalescer interface needs a note about handling opaque
// whiteouts properly.
