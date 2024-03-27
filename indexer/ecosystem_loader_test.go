package indexer

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore/toolkit/registry"
	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/plugin"
)

func init() {
	err := registry.Register(loaderName, &registry.Description[DynamicPlugin]{
		Default:      true,
		ConfigSchema: loaderSchema,
		New: func(ctx context.Context, f func(v any) error) (DynamicPlugin, error) {
			return newLoader(ctx, f)
		},
	})
	if err != nil {
		panic(err)
	}
}

func TestEcosystemLoader(t *testing.T) {
	var todo []string
	sys := os.DirFS(".")
	err := fs.WalkDir(sys, "testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ok, _ := path.Match(`*.config.json`, d.Name()); ok {
			todo = append(todo, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	checkConfig := func(fn string) func(*testing.T) {
		return func(t *testing.T) {
			b, err := os.ReadFile(fn)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			ctx = zlog.Test(ctx, t)
			cfg := plugin.Config{
				Configs: map[string][]byte{
					loaderName: b,
				},
				PoolSize: 1,
			}
			if len(b) == 0 {
				delete(cfg.Configs, loaderName)
			}
			pool, err := plugin.NewPool[DynamicPlugin](ctx, &cfg, loaderName)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			p, done, err := pool.Get(ctx, loaderName)
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			if err := p.Run(ctx); err != nil {
				t.Fatal(err)
			}

			for _, e := range *(p.(*ecosystemLoader)) {
				var spec EcosystemSpec
				var b []byte
				var err error
				switch {
				case e.Path != "" && e.Contents != "":
					t.Error(`cannot have both "path" and "contents"`)
					continue
				case e.Path != "":
					b, err = os.ReadFile(e.Path)
				case e.Contents != "":
					b = []byte(e.Contents)
				default:
					panic("unreachable")
				}
				if err != nil {
					t.Error(err)
					continue
				}
				if err := json.Unmarshal(b, &spec); err != nil {
					t.Error(err)
					continue
				}
				m, err := registry.GetDescription[EcosystemSpec](spec.Name)
				if err != nil {
					t.Error(err)
					continue
				}
				desc, ok := m[spec.Name]
				if !ok {
					t.Errorf("missing description for %q", spec.Name)
					continue
				}
				if got, want := e.Default, desc.Default; got != want {
					t.Errorf("default: got: %v, want: %v", got, want)
					continue
				}
				got, err := desc.New(ctx, func(_ any) error { return nil })
				if err != nil {
					t.Error(err)
					continue
				}

				if want := spec; !cmp.Equal(got, want) {
					t.Error(cmp.Diff(got, want))
				}
			}
		}
	}

	t.Run("null", checkConfig("/dev/null"))
	for _, fn := range todo {
		t.Run(strings.TrimSuffix(path.Base(fn), ".config.json"), checkConfig(fn))
	}
}
