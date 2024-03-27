package plugin

import (
	_ "embed"
	"fmt"
	"io"
	"strings"

	"github.com/quay/claircore/toolkit/registry"
	"github.com/quay/claircore/toolkit/urn"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// MustBeEmpty is the "urn:claircore:config:empty" schema.
//
// It ensures that passed objects are empty. This works with the [emptyObject]
// variable, which is the "zero value" returned out of the [Config] struct. If
// [emptyObject] changes, this schema must change with it.
//
//go:embed empty-schema.json
var MustBeEmpty string

// NewCompiler returns a JSON Schema compiler that can look up schemas by URN.
//
// Due to every type having a unique registry, this Compiler can only be used
// for the type supplied in the type parameter.
//
// This function may not be useful enough to warrant exporting.
func NewCompiler[T any](ds map[string]*registry.Description[T]) *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	c.ExtractAnnotations = true
	c.AssertFormat = true
	c.AssertContent = true
	c.LoadURL = func(s string) (io.ReadCloser, error) {
		if strings.HasPrefix(strings.ToLower(s), `urn:claircore:`) {
			n, err := urn.Normalize(s)
			if err != nil {
				return nil, fmt.Errorf("libindex: bad name: %w", err)
			}
			schema := MustBeEmpty
			if desc, ok := ds[n]; ok && desc.ConfigSchema != "" {
				schema = desc.ConfigSchema
			}
			return io.NopCloser(strings.NewReader(schema)), nil

		}
		return jsonschema.LoadURL(s)
	}
	return c
}
