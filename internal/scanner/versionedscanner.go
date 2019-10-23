package scanner

const (
	Package = "package"
)

// VersionedScanner can be imbeded into specific scanner types. This allows for methods and functions
// which only need to compare names and versions of scanners not to require each scanner type as an argument
type VersionedScanner interface {
	// unique name of the distribution scanner.
	Name() string
	// version of this scanner. this information will be persisted with the scan.
	Version() string
	// the kind of scanner. currently only package is implemented
	Kind() string
}

// VersionedScanners implements a list with construction methods
// not concurrency safe
type VersionedScanners []VersionedScanner

// PStoVS takes an array of PackageScanners and appends VersionedScanners with
// VersionScanner types.
func (vs *VersionedScanners) PStoVS(scnrs []PackageScanner) {
	temp := make([]VersionedScanner, 0)
	for _, scnr := range scnrs {
		temp = append(temp, scnr)
	}
	*vs = temp
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
	temp := make([]VersionedScanner, 0)
	for _, scnr := range scnrs {
		temp = append(temp, scnr)
	}
	*vs = temp
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
	temp := make([]VersionedScanner, 0)
	for _, scnr := range scnrs {
		temp = append(temp, scnr)
	}
	*vs = temp
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
