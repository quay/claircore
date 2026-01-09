package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const cachename = `matcher_wasm`

var (
	cachedir = sync.OnceValue(func() string {
		// This uses the systemd cache convention: CACHE_DIRECTORY is a
		// colon-separated list of directories for cache usage.
		//
		// See also: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RuntimeDirectory=
		dirlist, ok := os.LookupEnv("CACHE_DIRECTORY")
		if !ok {
			// If unset, try the user cache dir and a static prefix.
			if d, err := os.UserCacheDir(); err == nil { // NB on success
				dirlist = filepath.Join(d, "claircore")
			}
		}

		// For each list element, pick the one that is either:
		// 	- "Our" cache
		// 	- The shortest (read: most general) path
		//
		// If there are no elements in the list, this will result in using the
		// working directory.
		sz := math.MaxInt
		var p string
		for d := range strings.SplitSeq(dirlist, ":") {
			if filepath.Base(d) == cachename {
				return d
			}
			if len(d) < sz {
				sz = len(d)
				p = d
			}
		}
		return filepath.Join(p, cachename)
	})
	runtimeConfig = sync.OnceValue(func() wazero.RuntimeConfig {
		const pages = 1024 // 1024 * 64KiB == 64MiB
		cache, err := wazero.NewCompilationCacheWithDir(cachedir())
		if err != nil {
			cache = wazero.NewCompilationCache()
		}
		return wazero.NewRuntimeConfig().
			WithCloseOnContextDone(true).
			WithCompilationCache(cache).
			WithCustomSections(true).
			WithMemoryLimitPages(pages).
			WithMemoryCapacityFromMax(true).
			WithCoreFeatures(api.CoreFeaturesV2)
	})
)

var _ driver.Matcher = (*Matcher)(nil)

func NewMatcher(ctx context.Context, name string, wasm io.Reader) (*Matcher, error) {
	rt := wazero.NewRuntimeWithConfig(ctx, runtimeConfig())

	var binary []byte
	if b, ok := wasm.(*bytes.Buffer); ok {
		binary = b.Bytes()
	} else {
		var err error
		binary, err = io.ReadAll(wasm)
		if err != nil {
			return nil, err
		}
	}
	compiled, err := rt.CompileModule(ctx, binary)
	if err != nil {
		return nil, err
	}
	exp := compiled.ExportedFunctions()
	for _, name := range []string{
		"query",
		"filter",
		"vulnerable",
	} {
		def, ok := exp[name]
		if !ok {
			err = errors.Join(err, fmt.Errorf("missing export %q", name))
			continue
		}

		var in, out []api.ValueType
		switch name {
		case "query":
			in = []api.ValueType{}
			out = []api.ValueType{api.ValueTypeI32}
		case "filter":
			in = []api.ValueType{api.ValueTypeExternref}
			out = []api.ValueType{api.ValueTypeI32}
		case "vulnerable":
			in = []api.ValueType{api.ValueTypeExternref, api.ValueTypeExternref}
			out = []api.ValueType{api.ValueTypeI32}
		default:
			panic("unreachable")
		}

		if !slices.Equal(in, def.ParamTypes()) || !slices.Equal(out, def.ResultTypes()) {
			err = errors.Join(err, fmt.Errorf("incorrect signature for %q", name))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("wasm: validation failed: %w", err)
	}
	for _, m := range compiled.ImportedMemories() {
		println(m.Import())
	}

	m := &Matcher{
		name: name,
		rt:   rt,
	}

	//if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
	//	return nil, err
	//}
	env, err := rt.NewHostModuleBuilder("env").
		Compile(ctx)
	if err != nil {
		return nil, err
	}
	_ = env
	// env.ExportedMemories()["__linear_memory"]
	if _, err := buildHostV1Interface(rt).Instantiate(ctx); err != nil {
		return nil, err
	}

	config := wazero.NewModuleConfig()
	m.mod, err = rt.InstantiateModule(ctx, compiled, config)
	if err != nil {
		return nil, err
	}
	m.callFilter = m.mod.ExportedFunction("filter")

	return m, nil
}

type Matcher struct {
	name string
	rt   wazero.Runtime
	mod  api.Module

	callFilter api.Function

	validateRecord *claircore.IndexRecord
}

// Filter implements [driver.Matcher].
func (m *Matcher) Filter(record *claircore.IndexRecord) bool {
	var p runtime.Pinner
	defer p.Unpin()
	p.Pin(record)
	p.Pin(record.Distribution)
	p.Pin(record.Package)
	p.Pin(record.Package.Detector)
	p.Pin(record.Package.Source)
	p.Pin(record.Repository)

	ret, err := m.callFilter.Call(context.Background(), /*???*/
		api.EncodeExternref(uintptr(unsafe.Pointer(record))))
	if err != nil {
		panic(err)
	}
	ok := api.DecodeI32(ret[0]) != 0
	return ok
}

// Name implements [driver.Matcher].
func (m *Matcher) Name() string { return m.name }

// Query implements [driver.Matcher].
func (m *Matcher) Query() []driver.MatchConstraint {
	panic("unimplemented")
}

// Vulnerable implements [driver.Matcher].
func (m *Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	var p runtime.Pinner
	defer p.Unpin()
	p.Pin(record)
	p.Pin(record.Distribution)
	p.Pin(record.Package)
	p.Pin(record.Package.Detector)
	p.Pin(record.Package.Source)
	p.Pin(record.Repository)
	p.Pin(vuln)
	p.Pin(vuln.Dist)
	p.Pin(vuln.Package)
	p.Pin(vuln.Package.Detector)
	p.Pin(vuln.Package.Source)
	p.Pin(vuln.Range)
	p.Pin(vuln.Repo)

	panic("unimplemented")
}
