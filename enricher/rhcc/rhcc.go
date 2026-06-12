package rhcc

import (
	"context"
	"encoding/json"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/rhel/rhcc"
)

type Enricher struct{}

var (
	_ driver.Enricher = (*Enricher)(nil)
)

const (
	// Type is the type of data returned from the Enricher's Enrich method.
	Type = `message/vnd.clair.map.layer; enricher=clair.rhcc`
)

func (e *Enricher) Name() string { return "rhcc" }

func (e *Enricher) Enrich(ctx context.Context, g driver.EnrichmentGetter, r *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	rhccPkgs := make(map[string]string)
	for id, p := range r.Packages {
		if envs, ok := r.Environments[id]; ok && p.Kind == claircore.BINARY {
			for _, e := range envs {
				for _, repoID := range e.RepositoryIDs {
					repo := r.Repositories[repoID]
					if repo.Name == rhcc.GoldRepo.Name {
						rhccPkgs[id] = e.IntroducedIn.String()
						break
					}
				}
			}
		}
	}

	if len(rhccPkgs) == 0 {
		return Type, nil, nil
	}
	b, err := json.Marshal(rhccPkgs)
	if err != nil {
		return Type, nil, err
	}
	return Type, []json.RawMessage{b}, nil
}
