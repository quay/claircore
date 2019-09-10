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
	// package ID to Package pointer map to build a result
	items map[int]*claircore.Package
}

func NewStacker() *stacker {
	return &stacker{
		iteration: 0,
		counters:  make(map[int]int),
		items:     make(map[int]*claircore.Package),
	}
}

func (pi *stacker) Stack(pkgs []*claircore.Package) {
	if len(pkgs) == 0 {
		return
	}

	pi.iteration = pi.iteration + 1

	for _, pkg := range pkgs {
		pi.counters[pkg.ID] = pi.iteration
		pi.items[pkg.ID] = pkg
	}
}

func (pi *stacker) Result() []*claircore.Package {
	res := make([]*claircore.Package, 0)

	for id, iter := range pi.counters {
		if iter == pi.iteration {
			res = append(res, pi.items[id])
		}
	}

	return res
}
