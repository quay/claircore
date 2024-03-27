package libindex

import (
	"context"
	"sort"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/plugin"
)

type pluginSet struct {
	Coalescer    []string
	Distribution []string
	File         []string
	Package      []string
	Repository   []string
	Resolver     []string
}

// BUG(hank) It's more expensive than it needs to be to generate the set of
// plugins to be used in the process. The current setup re-uses code that does a
// lot of unneeded work.

func getPluginSet(ctx context.Context, cfg *plugin.Config, names ...string) (*pluginSet, error) {
	pool, err := plugin.NewPool[indexer.EcosystemSpec](ctx, cfg, names...)
	if err != nil {
		return nil, err
	}
	defer pool.Close()

	specs, done, err := pool.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	var ret pluginSet
	for _, spec := range specs {
		ret.Coalescer = append(ret.Coalescer, spec.Coalescer...)
		ret.Distribution = append(ret.Distribution, spec.Distribution...)
		ret.File = append(ret.File, spec.File...)
		ret.Package = append(ret.Package, spec.Package...)
		ret.Repository = append(ret.Repository, spec.Repository...)
		ret.Resolver = append(ret.Resolver, spec.Resolver...)
	}
	ret.Coalescer = filterNames(ret.Coalescer)
	ret.Distribution = filterNames(ret.Distribution)
	ret.File = filterNames(ret.File)
	ret.Package = filterNames(ret.Package)
	ret.Repository = filterNames(ret.Repository)
	ret.Resolver = filterNames(ret.Resolver)

	return &ret, nil
}

func filterNames(ns []string) []string {
	sort.Strings(ns)
	if len(ns) < 2 {
		return ns
	}
	i := 1
	for j := 1; j < len(ns); j++ {
		if ns[j] != ns[j-1] {
			if i != j {
				ns[i] = ns[j]
			}
			i++
		}
	}
	return ns[:i]
}
