package ubuntu

import (
	"compress/bzip2"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	_ driver.Updater      = (*updater)(nil)
	_ driver.Configurable = (*updater)(nil)
)

// Updater fetches and parses Ubuntu-flavored OVAL.
//
// Updaters are constructed exclusively by the [Factory].
type updater struct {
	// the url to fetch the OVAL db from
	url      string
	useBzip2 bool
	name     string
	id       string
	c        *http.Client
}

// Name implements [driver.Updater].
func (u *updater) Name() string {
	return fmt.Sprintf("ubuntu/updater/%s", u.name)
}

// Configure implements [driver.Configurable].
func (u *updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Updater.Configure",
		"updater", u.Name())
	u.c = c

	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.URL != "" {
		if _, err := url.Parse(cfg.URL); err != nil {
			return err
		}
		u.url = cfg.URL
		zlog.Info(ctx).
			Msg("configured database URL")
	}
	if cfg.UseBzip2 != nil {
		u.useBzip2 = *cfg.UseBzip2
	}

	return nil
}

// UpdaterConfig is the configuration for the updater.
//
// By convention, this is in a map called "ubuntu/updater/${RELEASE}", e.g.
// "ubuntu/updater/focal".
type UpdaterConfig struct {
	URL      string `json:"url" yaml:"url"`
	UseBzip2 *bool  `json:"use_bzip2" yaml:"use_bzip2"`
}

// Fetch implements [driver.Updater].
func (u *updater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Updater.Fetch",
		"database", u.url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request")
	}
	if fingerprint != "" {
		req.Header.Set("if-none-match", string(fingerprint))
	}

	// fetch OVAL xml database
	resp, err := u.c.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("ubuntu: failed to retrieve OVAL database: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if fp := string(fingerprint); fp == "" || fp != resp.Header.Get("etag") {
			zlog.Info(ctx).Msg("fetching latest oval database")
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil, fingerprint, driver.Unchanged
	default:
		return nil, "", fmt.Errorf("ubuntu: unexpected response: %s", resp.Status)
	}

	fp := resp.Header.Get("etag")
	f, err := tmp.NewFile("", "ubuntu.")
	if err != nil {
		return nil, "", err
	}
	var r io.Reader = resp.Body
	if u.useBzip2 {
		r = bzip2.NewReader(r)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("ubuntu: failed to read http body: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("ubuntu: failed to seek body: %w", err)
	}

	zlog.Info(ctx).Msg("fetched latest oval database successfully")
	return f, driver.Fingerprint(fp), err
}

// Parse implements [driver.Updater].
func (u *updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "ubuntu/Updater.Parse")
	zlog.Info(ctx).Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	dec := xml.NewDecoder(r)
	dec.CharsetReader = xmlutil.CharsetReader
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("ubuntu: unable to decode OVAL document: %w", err)
	}
	zlog.Debug(ctx).Msg("xml decoded")

	nameLookupFunc := func(def oval.Definition, name *oval.DpkgName) []string {
		// if the dpkginfo_object>name field has a var_ref it indicates
		// a variable lookup for all packages affected by this vuln is necessary.
		//
		// if the name.Ref field is empty it indicates a single package is affected
		// by the vuln and that package's name is in name.Body.
		var ns []string
		if len(name.Ref) == 0 {
			ns = append(ns, name.Body)
			return ns
		}
		_, i, err := root.Variables.Lookup(name.Ref)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("could not lookup variable id")
			return ns
		}
		consts := root.Variables.ConstantVariables[i]
		for _, v := range consts.Values {
			ns = append(ns, v.Body)
		}
		return ns
	}

	protoVulns := func(def oval.Definition) ([]*claircore.Vulnerability, error) {
		vs := []*claircore.Vulnerability{}
		v := &claircore.Vulnerability{
			Updater:            u.Name(),
			Name:               def.Title,
			Description:        def.Description,
			Issued:             def.Advisory.Issued.Date,
			Links:              ovalutil.Links(def),
			NormalizedSeverity: normalizeSeverity(def.Advisory.Severity),
			Dist:               lookupDist(u.id),
		}
		vs = append(vs, v)
		return vs, nil
	}
	vulns, err := ovalutil.DpkgDefsToVulns(ctx, &root, protoVulns, nameLookupFunc)
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func normalizeSeverity(severity string) claircore.Severity {
	switch severity {
	case "Negligible":
		return claircore.Negligible
	case "Low":
		return claircore.Low
	case "Medium":
		return claircore.Medium
	case "High":
		return claircore.High
	case "Critical":
		return claircore.Critical
	default:
	}
	return claircore.Unknown
}
