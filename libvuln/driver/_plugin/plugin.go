// Plugin is an example libvuln plugin.
//
// See the libvuln/driver documentation for how these functions are called.
//
// Note that the plugin loader returns pointers to the named values, so
// declaring a variable of type `*T` will result in the loader receiving a value
// of type `**T`.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

const Name = `testplugin`

// Matcher example:

// MatcherFactory is the entrypoint for a matcher plugin.
var MatcherFactory Factory

type Factory struct{}

var _ driver.MatcherFactory = (*Factory)(nil)

func (*Factory) Matcher(ctx context.Context) ([]driver.Matcher, error) {
	zlog.Info(ctx).Msg("hello from a plugin")
	return []driver.Matcher{&Matcher{}}, nil
}

type Matcher struct{}

var _ driver.Matcher = (*Matcher)(nil)

func (*Matcher) Name() string {
	return Name
}

func (*Matcher) Filter(r *claircore.IndexRecord) bool {
	return false
}

func (*Matcher) Query() []driver.MatchConstraint {
	return nil
}

func (*Matcher) Vulnerable(ctx context.Context, r *claircore.IndexRecord, v *claircore.Vulnerability) (bool, error) {
	return false, nil
}

func (*Matcher) Configure(ctx context.Context, _ driver.MatcherConfigUnmarshaler, _ *http.Client) error {
	zlog.Info(ctx).
		Msg("hello from " + Name)
	return nil
}

func (*Matcher) QueryRemoteMatcher(ctx context.Context, _ []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	zlog.Warn(ctx).
		Msg("would phone home here")
	return nil, nil
}

// Enricher example:

var Enricher enricher

type enricher struct{}

var _ driver.Enricher = (*enricher)(nil)

func (*enricher) Name() string {
	return Name
}

func (*enricher) Enrich(context.Context, driver.EnrichmentGetter, *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	return "", nil, nil
}

// Updater example:

var UpdaterSetFactory Updaters

type Updaters struct{}

var _ driver.UpdaterSetFactory = (*Updaters)(nil)

func (*Updaters) UpdaterSet(context.Context) (driver.UpdaterSet, error) {
	set := driver.NewUpdaterSet()
	set.Add(&Updater{})
	return set, nil
}

type Updater struct {
	driver.NoopUpdater
}

var (
	_ driver.Updater           = (*Updater)(nil)
	_ driver.EnrichmentUpdater = (*Updater)(nil)
)

func (*Updater) Name() string {
	return Name
}

func (*Updater) FetchEnrichment(context.Context, driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	return nil, "", nil
}

func (*Updater) ParseEnrichment(context.Context, io.ReadCloser) ([]driver.EnrichmentRecord, error) {
	return nil, nil
}
