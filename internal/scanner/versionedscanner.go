package scanner

const (
	Package = "package"
)

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
