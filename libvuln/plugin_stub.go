//go:build !((linux && cgo) || (darwin && cgo) || (freebsd && cgo))
// +build !linux !cgo
// +build !darwin !cgo
// +build !freebsd !cgo

// Keep the above build constraint updated along with the one in plugin.go and
// the stdlib's plugin/plugin_dlopen.go.

package libvuln

import (
	"context"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
)

func enabledLog(ctx context.Context) func() {
	return func() { zlog.Info(ctx).Msg("plugin loading disabled") }
}

func loadMatchers(ctx context.Context, root string) ([]driver.Matcher, error) {
	pluginlog.Do(enabledLog(ctx))
	return nil, nil
}

func loadEnrichers(ctx context.Context, root string) ([]driver.Enricher, error) {
	pluginlog.Do(enabledLog(ctx))
	return nil, nil
}

func loadUpdaters(ctx context.Context, root string) (map[string]driver.UpdaterSetFactory, error) {
	pluginlog.Do(enabledLog(ctx))
	return nil, nil
}
