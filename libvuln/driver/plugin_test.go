package driver_test

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type enricher struct{}

func (*enricher) Name() string {
	return `example-enricher`
}

func (*enricher) Enrich(context.Context, driver.EnrichmentGetter, *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	return "application/json", []json.RawMessage{json.RawMessage(`{}`)}, nil
}

var Enricher enricher

func Example_plugin() {
	var e driver.Enricher
	// In Libvuln's loading code, the equivalent of the below is happening:
	/*
		p, err := plugin.Open("self.so")
		if err != nil {
			panic(err)
		}
		i, err := p.Lookup("Enricher")
		if err != nil {
			panic(err)
		}
		e = i.(driver.Enricher)
	*/
	// For this example, we'll just point at the package-level variable
	// directly.
	e = &Enricher
	fmt.Println(e.Name())
	// Output:
	// example-enricher
}
