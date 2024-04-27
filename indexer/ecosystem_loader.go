package indexer

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/quay/claircore/toolkit/registry"
)

// TODO(hank) Find a better home for this.

type ecosystemLoader []loadEntry

type loadEntry struct {
	Path     string `json:"path"`
	Contents string `json:"contents"`
	Default  bool   `json:"default"`
}

var (
	//go:embed loader_schema.json
	loaderSchema string

	// Ecosystem is a DynamicPlugin hook for loading EcosystemSpecs from JSON
	// objects.
	//
	//plugintool:register indexer
	loaderDescription = registry.Description[DynamicPlugin]{
		Default:      true,
		ConfigSchema: loaderSchema,
		New: func(ctx context.Context, f func(v any) error) (DynamicPlugin, error) {
			return newLoader(ctx, f)
		},
	}
)

const loaderName = `urn:claircore:indexer:dynamicplugin:ecosystem`

func newLoader(ctx context.Context, f func(v any) error) (*ecosystemLoader, error) {
	var l ecosystemLoader
	if err := f(&l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Run implements [indexer.DynamicPlugin].
func (l *ecosystemLoader) Run(ctx context.Context) error {
	var errs []error
	for n, i := range *l {
		var b []byte
		var err error
		switch {
		case i.Path != "" && i.Contents != "":
			err = fmt.Errorf(`element %d contains "path" and "contents" keys`, n)
		case i.Path != "":
			b, err = os.ReadFile(i.Path)
		case i.Contents != "":
			b = []byte(i.Contents)
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var spec EcosystemSpec
		if err := json.Unmarshal(b, &spec); err != nil {
			errs = append(errs, err)
			continue
		}
		err = registry.Register(spec.Name, &registry.Description[EcosystemSpec]{
			Default: i.Default,
			New: func(_ context.Context, f func(any) error) (EcosystemSpec, error) {
				return spec, f(new(struct{}))
			},
		})
		switch {
		case errors.Is(err, nil): // OK
		case errors.Is(err, registry.ErrAlreadyRegistered): // Skip
		default:
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("ecosystem: %w", err)
	}
	return nil
}
