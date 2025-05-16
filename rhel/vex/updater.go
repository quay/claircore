package vex

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Updater           = (*Updater)(nil)
	_ driver.Configurable      = (*Updater)(nil)
	_ driver.DeltaUpdater      = (*Updater)(nil)
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
)

const (
	// BaseURL is the base url for the Red Hat VEX security data.
	//
	//doc:url updater
	BaseURL = "https://security.access.redhat.com/data/csaf/v2/vex/"

	defaultCompressedFileTimeout = 2 * time.Minute
	latestFile                   = "archive_latest.txt"
	changesFile                  = "changes.csv"
	deletionsFile                = "deletions.csv"
	lookBackToYear               = 2014
	repoKey                      = "rhel-cpe-repository"
	updaterVersion               = "5"
)

// Factory creates an Updater to process all of the Red Hat VEX data.
//
// [Configure] must be called before [UpdaterSet].
type Factory struct {
	c                     *http.Client
	base                  *url.URL
	compressedFileTimeout time.Duration
}

// UpdaterSet constructs one Updater
func (f *Factory) UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	u := &Updater{
		url:                   f.base,
		client:                f.c,
		compressedFileTimeout: f.compressedFileTimeout,
	}
	err := us.Add(u)
	if err != nil {
		return us, err
	}
	return us, nil
}

// FactoryConfig is the configuration honored by the Factory.
//
// The URL is where the updater expects the VEX data to be published
// (and must end with a slash).
type FactoryConfig struct {
	// URL indicates the base URL for the VEX.
	//
	// Must include the trailing slash.
	URL string `json:"url" yaml:"url"`
	// CompressedFileTimeout sets the timeout for downloading the compressed VEX file.
	CompressedFileTimeout claircore.Duration `json:"compressed_file_timeout" yaml:"compressed_file_timeout"`
}

// Configure implements driver.Configurable
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	var err error
	u := BaseURL
	if cfg.URL != "" {
		u = cfg.URL
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
	}
	f.base, err = url.Parse(u)
	if err != nil {
		return err
	}

	f.compressedFileTimeout = defaultCompressedFileTimeout
	if cfg.CompressedFileTimeout != 0 {
		f.compressedFileTimeout = time.Duration(cfg.CompressedFileTimeout)
	}
	return nil
}

// Updater is responsible from reading VEX data served at the URL
// and creating vulnerabilities.
type Updater struct {
	url                   *url.URL
	client                *http.Client
	compressedFileTimeout time.Duration
}

// fingerprint is used to track the state of the changes.csv and deletions.csv endpoints.
//
// The spec (https://www.rfc-editor.org/rfc/rfc9110.html#name-etag) mentions
// that there is no need for the client to be aware of how each entity tag
// is constructed, however, it mentions that servers should avoid backslashes.
// Hence, the `\` character is used as a separator when stringifying.
type fingerprint struct {
	changesEtag, deletionsEtag string
	requestTime                time.Time
	version                    string
}

// ParseFingerprint takes a generic driver.Fingerprint and creates a vex.fingerprint.
// The string format saved in the DB is returned by the fingerprint.String() method.
func parseFingerprint(in driver.Fingerprint) (*fingerprint, error) {
	fp := string(in)
	if fp == "" {
		return &fingerprint{}, nil
	}
	f := strings.Split(fp, `\`)
	if len(f) != 4 {
		return nil, errors.New("could not parse fingerprint")
	}
	rt, err := time.Parse(time.RFC3339, f[2])
	if err != nil {
		return nil, fmt.Errorf("could not parse fingerprint's requestTime: %w", err)
	}
	return &fingerprint{
		changesEtag:   f[0],
		deletionsEtag: f[1],
		requestTime:   rt,
		version:       f[3],
	}, nil
}

// String represents a fingerprint in string format with `\` acting as the delimiter.
func (fp *fingerprint) String() string {
	return fp.changesEtag + `\` + fp.deletionsEtag + `\` + fp.requestTime.Format(time.RFC3339) + `\` + fp.version
}

// Name returns the name string of the Updater.
func (u *Updater) Name() string {
	return "rhel-vex"
}

// UpdaterConfig is the configuration for the updater.
type UpdaterConfig struct {
	// URL overrides any discovered URL for the JSON file.
	URL string `json:"url" yaml:"url"`
}

// Configure implements driver.Configurable.
func (u *Updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/vex/Updater.Configure")

	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}
	bu := BaseURL
	if cfg.URL != "" {
		bu = cfg.URL
	}
	url, err := url.Parse(bu)
	if err != nil {
		return err
	}
	u.url = url
	zlog.Info(ctx).
		Str("updater", u.Name()).
		Msg("configured url")

	u.client = c
	return nil
}
