package indexer

import (
	"context"
	"net/http"
)

const (
	Package = "package"
)

// VersionedScanner can be embedded into specific scanner types. This allows for
// methods and functions which only need to compare names and versions of
// scanners not to require each scanner type as an argument.
type VersionedScanner interface {
	// unique name of the distribution scanner.
	Name() string
	// version of this scanner. this information will be persisted with the scan.
	Version() string
	// the kind of scanner. currently only package is implemented
	Kind() string
}

// ConfigDeserializer can be thought of as an Unmarshal function with the byte
// slice provided.
//
// This will typically be something like (*json.Decoder).Decode.
type ConfigDeserializer func(interface{}) error

// RPCScanner is an interface scanners can implement to receive configuration
// and denote that they expect to be able to talk to the network at run time.
type RPCScanner interface {
	Configure(context.Context, ConfigDeserializer, *http.Client) error
}

// ConfigurableScanner is an interface scanners can implement to receive
// configuration.
type ConfigurableScanner interface {
	Configure(context.Context, ConfigDeserializer) error
}

// VersionedScanners implements a list with construction methods
// not concurrency safe
type VersionedScanners []VersionedScanner

func (vs *VersionedScanners) PStoVS(scnrs []PackageScanner) {
	n := len(scnrs)
	if cap(*vs) < n {
		*vs = make([]VersionedScanner, n)
	} else {
		*vs = (*vs)[:n]
	}
	for i := 0; i < n; i++ {
		(*vs)[i] = scnrs[i]
	}
}

// VStoPS returns an array of PackageScanners
func (vs VersionedScanners) VStoPS() []PackageScanner {
	out := make([]PackageScanner, len(vs))
	for _, vscnr := range vs {
		out = append(out, vscnr.(PackageScanner))
	}
	return out
}

// DStoVS takes an array of DistributionScanners and appends VersionedScanners with
// VersionScanner types.
func (vs *VersionedScanners) DStoVS(scnrs []DistributionScanner) {
	n := len(scnrs)
	if cap(*vs) < n {
		*vs = make([]VersionedScanner, n)
	} else {
		*vs = (*vs)[:n]
	}
	for i := 0; i < n; i++ {
		(*vs)[i] = scnrs[i]
	}
}

// VStoDS returns an array of DistributionScanners
func (vs VersionedScanners) VStoDS() []DistributionScanner {
	out := make([]DistributionScanner, len(vs))
	for _, vscnr := range vs {
		out = append(out, vscnr.(DistributionScanner))
	}
	return out
}

// RStoVS takes an array of RepositoryScanners and appends VersionedScanners with
// VersionScanner types.
func (vs *VersionedScanners) RStoVS(scnrs []RepositoryScanner) {
	n := len(scnrs)
	if cap(*vs) < n {
		*vs = make([]VersionedScanner, n)
	} else {
		*vs = (*vs)[:n]
	}
	for i := 0; i < n; i++ {
		(*vs)[i] = scnrs[i]
	}
}

// VStoRS returns an array of RepositoryScanners
func (vs VersionedScanners) VStoRS() []RepositoryScanner {
	out := make([]RepositoryScanner, len(vs))
	for _, vscnr := range vs {
		out = append(out, vscnr.(RepositoryScanner))
	}
	return out
}

// MergeVS merges lists of scanners into a single list of VersionedScanner types
func MergeVS(pscnr []PackageScanner, dscnr []DistributionScanner, rscnr []RepositoryScanner) VersionedScanners {
	out := make([]VersionedScanner, 0)
	for _, ps := range pscnr {
		out = append(out, VersionedScanner(ps))
	}
	for _, ds := range dscnr {
		out = append(out, VersionedScanner(ds))
	}
	for _, rs := range rscnr {
		out = append(out, VersionedScanner(rs))
	}
	return out
}
