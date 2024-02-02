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

	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Updater           = (*VEXUpdater)(nil)
	_ driver.Configurable      = (*VEXUpdater)(nil)
	_ driver.DeltaUpdater      = (*VEXUpdater)(nil)
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
)

const (
	baseURL        = "https://access.redhat.com/security/data/csaf/beta/vex/"
	latestFile     = "archive_latest.txt"
	lookBackToYear = 2005
	repoKey        = "rhel-cpe-repository"
)

type Factory struct {
	c    *http.Client
	base *url.URL
}

// UpdaterSet constructs one VEXUpdater
func (f *Factory) UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	u := &VEXUpdater{
		url:    f.base,
		client: f.c,
	}
	err := us.Add(u)
	if err != nil {
		return us, err
	}
	return us, nil
}

type FactoryConfig struct {
	// URL indicates the base URL for the SecDB layout. It should have a trailing slash.
	URL string `json:"url" yaml:"url"`
}

func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	var err error
	u := baseURL
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
	return nil
}

type VEXUpdater struct {
	url    *url.URL
	client *http.Client
}

type fingerprint struct {
	// This is a "stable" file that we can track
	changesEtag string
	requestTime time.Time
}

func NewFingerprint(etag string, requestTime time.Time) *fingerprint {
	return &fingerprint{
		changesEtag: etag,
		requestTime: requestTime,
	}
}

func ParseFingerprint(fp string) (*fingerprint, error) {
	// On the fence with this or adding a specialist error
	if fp == "" {
		return &fingerprint{}, nil
	}
	f := strings.Split(fp, "_")
	if len(f) != 2 {
		return nil, errors.New("could not parse fingerprint")
	}
	rt, err := time.Parse(time.RFC3339, f[1])
	if err != nil {
		return nil, fmt.Errorf("could not parse fingerprint's requestTime")
	}
	return &fingerprint{
		changesEtag: f[0],
		requestTime: rt,
	}, nil
}

func (fp *fingerprint) String() string {
	return fp.changesEtag + "_" + fp.requestTime.Format(time.RFC3339)
}

func (u *VEXUpdater) Name() string {
	return "rhel-vex"
}

type UpdaterConfig struct {
	// URL overrides any discovered URL for the JSON file.
	URL string `json:"url" yaml:"url"`
}

// Configure implements driver.Configurable.
func (u *VEXUpdater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/VEXUpdater.Configure")

	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}
	bu := baseURL
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
	u.client.Timeout = 5 * time.Second
	return nil
}
