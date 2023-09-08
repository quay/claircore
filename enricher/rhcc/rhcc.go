package rhcc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type Enricher struct{}

var (
	_ driver.Enricher = (*Enricher)(nil)
)

const (
	// Type is the type of data returned from the Enricher's Enrich method.
	Type = `message/vnd.clair.map.layer; enricher=clair.rhcc schema=??`
)

func (e *Enricher) Name() string { return "rhcc" }

func (e *Enricher) Enrich(ctx context.Context, g driver.EnrichmentGetter, r *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	problematicPkgs := make(map[string]string)
	for id, p := range r.Packages {
		if p.RepositoryHint == "rhcc" && p.Kind == claircore.BINARY {
			if envs, ok := r.Environments[id]; ok {
				for _, e := range envs {
					problematicPkgs[e.IntroducedIn.String()] = id
				}
			} else {
				return Type, nil, fmt.Errorf("no environment found for package %s", id)
			}
		}
	}

	b, err := json.Marshal(problematicPkgs)
	if err != nil {
		return Type, nil, err
	}
	return Type, []json.RawMessage{b}, nil
}
