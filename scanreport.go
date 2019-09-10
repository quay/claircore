package claircore

// ScanReport aggregates the results of a container scan at the image layer and at the individual layer level.
type ScanReport struct {
	// the manifest hash this scan result is assocaited with
	Hash string `json:"manifest_hash"`
	// the current state of the scan.
	State string `json:"state"`
	// packages found after stacking all layers
	Packages map[int]*Package `json:"packages"`
	// layer hash that introduced the given package id
	PackageIntroduced map[int]string `json:"package_introduced"`
	// whether the scan was successful
	Success bool `json:"success"`
	// the first fatal error that occured during a scan process
	Err string `json:"err"`
}
