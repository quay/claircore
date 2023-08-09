package libindex

import (
	"context"
	"testing"

	"github.com/quay/claircore/toolkit/registry"
	"github.com/quay/zlog"

	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/plugin"
)

func TestInitEcosystems(t *testing.T) {
	const name = `urn:claircore:indexer:ecosystemspec:init-test`
	ctx := zlog.Test(context.Background(), t)
	type Config struct {
		Test bool `json:"test"`
	}
	desc := registry.Description[indexer.EcosystemSpec]{
		ConfigSchema: `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "` + name + `",
  "title": "EcosystemSpec Configuration",
  "description": "Example configuration JSON Schema.\n\nThis field may be automatically displayed to operators in the future.",
  "type": "object",
  "properties": {
    "test": {
      "description": "Boolean indicating if this is a test or not.",
      "type": "boolean"
    }
  },
  "required":["test"]
}`,
		New: func(ctx context.Context, f func(any) error) (indexer.EcosystemSpec, error) {
			spec := indexer.EcosystemSpec{
				Name: name,
			}
			var cfg Config
			if err := f(&cfg); err != nil {
				return spec, err
			}
			t.Logf("configured new instance: test? %v", cfg.Test)
			return spec, nil
		},
	}
	if err := registry.Register(name, &desc); err != nil {
		t.Fatal(err)
	}
	cfg := plugin.Config{
		Configs: map[string][]byte{
			name: []byte(`{"test":true}`),
		},
		PoolSize: 1,
	}
	if _, err := getPluginSet(ctx, &cfg, name); err != nil {
		t.Error(err)
	}

	cfg.Configs[name] = []byte(`{"test":false}`)
	if _, err := getPluginSet(ctx, &cfg, name); err != nil {
		t.Error(err)
	}
}
