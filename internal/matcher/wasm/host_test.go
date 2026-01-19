package wasm

import (
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

func init() {
	// Override the disk caching for tests.
	cache = sync.OnceValue(wazero.NewCompilationCache)
}

func TestHostV1(t *testing.T) {
	ctx := t.Context()
	rConfig := runtimeConfig()
	rt := wazero.NewRuntimeWithConfig(ctx, rConfig)
	mod, err := buildHostV1Interface(rt).Compile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fns := mod.ExportedFunctions()
	keys := slices.Collect(maps.Keys(fns))
	slices.Sort(keys)
	var b strings.Builder

	writelist := func(ts []api.ValueType, ns []string) {
		b.WriteByte('(')
		for i := range ts {
			if i != 0 {
				b.WriteString(", ")
			}
			b.WriteString(ns[i])
			b.WriteString(": ")
			switch ts[i] {
			case api.ValueTypeExternref:
				b.WriteString("externref")
			case api.ValueTypeI32:
				b.WriteString("i32")
			case api.ValueTypeI64:
				b.WriteString("i64")
			case api.ValueTypeF32:
				b.WriteString("f32")
			case api.ValueTypeF64:
				b.WriteString("f64")
			default:
				b.WriteString("???")
			}
		}
		b.WriteByte(')')
	}
	for _, k := range keys {
		v := fns[k]
		b.Reset()
		b.WriteString(v.DebugName())
		writelist(v.ParamTypes(), v.ParamNames())
		b.WriteString(" -> ")
		writelist(v.ResultTypes(), v.ResultNames())

		t.Log(b.String())
	}
}

func TestTrivial(t *testing.T) {
	ctx := t.Context()
	f, err := os.Open("testdata/trivial.wasm")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	m, err := NewMatcher(ctx, "trivial", f)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Query", func(t *testing.T) {
		want := []driver.MatchConstraint{driver.PackageName, driver.HasFixedInVersion}
		got := m.Query()
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	t.Log(`testing trvial matcher: "Filter() == true" when "len(IndexRecord.Package.Name) != 0"`)
	r := &claircore.IndexRecord{
		Package: &claircore.Package{Name: "pkg"},
	}
	ok := m.Filter(r)
	t.Logf("package name %q: %v", r.Package.Name, ok)
	if !ok {
		t.Fail()
	}

	r.Package = new(claircore.Package)
	ok = m.Filter(r)
	t.Logf("package name %q: %v", r.Package.Name, ok)
	if ok {
		t.Fail()
	}
}
