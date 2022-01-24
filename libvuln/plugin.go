//go:build (linux && cgo) || (darwin && cgo) || (freebsd && cgo)
// +build linux,cgo darwin,cgo freebsd,cgo

package libvuln

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

func findPlugins(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var r []string
	for _, ent := range ents {
		switch {
		case ent.IsDir():
			continue
		case !strings.HasSuffix(ent.Name(), ".so"):
			continue
		}
		r = append(r, filepath.Join(dir, ent.Name()))
	}
	return r, nil
}

func enabledLog(ctx context.Context) func() {
	return func() { zlog.Info(ctx).Msg("plugin loading enabled") }
}

// Here's the generic version we can't use yet. This version lets us put the
// assertion into the shared function.
/*
func loadFrom[T any](ctx context.Context, file, entry string) (T, error) {
	var r T
	zlog.Debug(ctx).
		Str("file", file).
		Msg("loading plugin")
	dl, err := plugin.Open(file)
	if err != nil {
		return r, err
	}
	v, err := dl.Lookup(entry)
	if err != nil {
		zlog.Debug(ctx).
			Str("file", file).
			Msg("missing entrypoint, skipping")
		return r, nil
	}
	var ok bool
	r, ok = v.(T)
	if !ok {
		return r, fmt.Errorf("unable to find %T at %q in %q", r, entry, file)
	}
	return r, nil
}
*/

func loadFrom(ctx context.Context, file, entry string) (interface{}, error) {
	zlog.Debug(ctx).
		Str("file", file).
		Msg("loading plugin")
	dl, err := plugin.Open(file)
	if err != nil {
		return nil, err
	}
	v, err := dl.Lookup(entry)
	if err != nil {
		zlog.Debug(ctx).
			Str("file", file).
			Msg("missing entrypoint, skipping")
		return nil, nil
	}
	return v, nil
}

func loadMatchers(ctx context.Context, root string) ([]driver.Matcher, error) {
	pluginlog.Do(enabledLog(ctx))
	var ret []driver.Matcher
	ns, err := findPlugins(root)
	if err != nil {
		return nil, err
	}
	for _, n := range ns {
		v, err := loadFrom(ctx, n, driver.MatcherEntrypoint)
		switch {
		case err != nil:
			return nil, err
		case v == nil:
			continue
		}
		mf, ok := v.(driver.MatcherFactory)
		if !ok {
			return nil, fmt.Errorf("unable to find %T at %q in %q", mf, driver.MatcherEntrypoint, n)
		}
		ms, err := mf.Matcher(ctx)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ms...)
	}
	zlog.Info(ctx).
		Msg("loaded matcher plugins")
	return ret, nil
}

func loadEnrichers(ctx context.Context, root string) ([]driver.Enricher, error) {
	pluginlog.Do(enabledLog(ctx))
	var ret []driver.Enricher
	ns, err := findPlugins(root)
	if err != nil {
		return nil, err
	}
	for _, n := range ns {
		v, err := loadFrom(ctx, n, driver.EnricherEntrypoint)
		switch {
		case err != nil:
			return nil, err
		case v == nil:
			continue
		}
		var e driver.Enricher
		var ok bool
		e, ok = v.(driver.Enricher)
		if !ok {
			return nil, fmt.Errorf("unable to find %T at %q in %q", e, driver.EnricherEntrypoint, n)
		}
		ret = append(ret, e)
	}
	return ret, nil
}

func loadUpdaters(ctx context.Context, root string) (map[string]driver.UpdaterSetFactory, error) {
	pluginlog.Do(enabledLog(ctx))
	ret := make(map[string]driver.UpdaterSetFactory)
	ns, err := findPlugins(root)
	if err != nil {
		return nil, err
	}
	for _, n := range ns {
		v, err := loadFrom(ctx, n, driver.UpdaterEntrypoint)
		switch {
		case err != nil:
			return nil, err
		case v == nil:
			continue
		}
		usf, ok := v.(driver.UpdaterSetFactory)
		if !ok {
			return nil, fmt.Errorf("unable to find %T at %q in %q", usf, driver.UpdaterEntrypoint, n)
		}
		ret[mkName(n)] = usf
	}
	return ret, nil
}

func mkName(n string) string {
	return `plugin/` + strings.TrimSuffix(filepath.Base(n), ".so")
}
