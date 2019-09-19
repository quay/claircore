package scanner

import "github.com/quay/claircore"

// stacker keeps track of package addition and removal between calls of stack().
// a call to result() will produce any packages which existed in all calls where
// the package array was larger then 0 elements.
type stacker struct {
	// the number in which the stack method has been called
	// with a list of len > 0
	iteration int
	// holds a mapping between package ids and counts.
	counters map[int]int
	// signifies if we are working on the base layer
	baseLayer bool
	// package ID to Package pointer map to build a result
	packages map[int]*claircore.Package
	// keeps track of the distribution information associated with a package.
	distByPackage map[int]*claircore.Distribution
	// keeps track of the first time we see a package
	introducedIn map[int]string
}

func NewStacker() *stacker {
	return &stacker{
		iteration:     0,
		counters:      make(map[int]int),
		baseLayer:     true,
		packages:      make(map[int]*claircore.Package),
		distByPackage: make(map[int]*claircore.Distribution),
		introducedIn:  make(map[int]string),
	}
}

func (pi *stacker) Stack(layer *claircore.Layer, pkgs []*claircore.Package) {
	if len(pkgs) == 0 {
		return
	}

	pi.iteration = pi.iteration + 1

	for _, pkg := range pkgs {
		pi.counters[pkg.ID] = pi.iteration
		pi.packages[pkg.ID] = pkg

		// record if this is the first time we see this package
		if _, ok := pi.introducedIn[pkg.ID]; !ok {
			pi.introducedIn[pkg.ID] = layer.Hash
		}

		// first call to Stack will signify its the base layer. get initial distribution info
		// for the package.
		if pi.baseLayer {
			pi.distByPackage[pkg.ID] = pkg.Dist
			pi.baseLayer = false
			continue
		}

		// if this is not the base layer and we see a non-empty distribution
		// update the package's dist info
		if !checkEmptyDist(pkg.Dist) {
			pi.distByPackage[pkg.ID] = pkg.Dist
		}
	}
}

func (pi *stacker) Result() ([]*claircore.Package, map[int]string) {
	res := make([]*claircore.Package, 0)

	for id, iter := range pi.counters {
		if iter == pi.iteration {
			stackedPkg := pi.packages[id]
			stackedPkg.Dist = pi.distByPackage[id]
			res = append(res, pi.packages[id])
		}
	}

	return res, pi.introducedIn
}

func checkEmptyDist(dist *claircore.Distribution) bool {
	if dist.DID == "" &&
		dist.Name == "" &&
		dist.Version == "" &&
		dist.VersionCodeName == "" &&
		dist.VersionID == "" &&
		dist.Arch == "" {
		return true
	}

	return false
}
