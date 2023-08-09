package plugin_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/plugin"
	"github.com/quay/claircore/internal/plugin/internal/testplugin"
)

func TestSchema(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	cfg := plugin.Config{
		Configs:  map[string][]byte{},
		PoolSize: 1,
	}

	t.Run("Success", func(t *testing.T) {
		pool, err := plugin.NewPool[testplugin.Interface](ctx, &cfg, testplugin.Name)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		res, done, err := pool.Get(ctx, testplugin.Name)
		if err != nil {
			t.Fatal(err)
		}
		defer done()
		got, want := fmt.Sprintf("%T", res), testplugin.Type
		t.Logf("got: %s, want: %s", got, want)
		if got != want {
			t.Fail()
		}
	})

	cfg.Configs[testplugin.Name] = []byte(`[]`)

	t.Run("Failure", func(t *testing.T) {
		_, err := plugin.NewPool[testplugin.Interface](ctx, &cfg, testplugin.Name)
		t.Log(err)
		if err == nil {
			t.Fatal("got: <nil>, want: <schema validation failed>")
		}
	})
}

func TestResolverPool(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	cfg := plugin.Config{
		Configs:  map[string][]byte{},
		PoolSize: 1,
	}
	pool, err := plugin.NewPool[testplugin.Interface](ctx, &cfg, testplugin.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	res, done, err := pool.Get(ctx, testplugin.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	got, want := fmt.Sprintf("%T", res), testplugin.Type
	t.Logf("got: %s, want: %s", got, want)
	if got != want {
		t.Fail()
	}
}
