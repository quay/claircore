package execupdater

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/quay/zlog"
	"golang.org/x/exp/jsonrpc2"

	"github.com/quay/claircore/updater/driver/v1"
)

var Factory driver.UpdaterFactory

func init() {
	var ps []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		ps = append(ps, dir)
	}
	Factory = &factory{
		ps: ps,
	}
}

type factory struct {
	ps []string
}

func (*factory) Name() string {
	return `exec`
}

func (f *factory) Create(ctx context.Context, cf driver.ConfigUnmarshaler) (driver.UpdaterSet, error) {
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return nil, err
	}

	for _, dir := range f.ps {
		pat := filepath.Join(dir, Pattern)
		ms, err := filepath.Glob(pat)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %w", pat, err)
		}
		cfg.Exec = append(cfg.Exec, ms...)
	}
	n := 0
	for _, x := range cfg.Exec {
		x, err := exec.LookPath(x)
		if err != nil {
			zlog.Debug(ctx).Err(err).Msg("skipping command")
			continue
		}
		cfg.Exec[n] = x
		n++
	}
	cfg.Exec = cfg.Exec[:n]

	set := make(driver.UpdaterSet)
	for _, x := range cfg.Exec {
		ectx, done := context.WithTimeout(ctx, 1*time.Second)
		cmd := exec.CommandContext(ectx, x, "config")
		out, err := cmd.Output()
		done()
		if err != nil {
			// log
			continue
		}
		var cfg ExecConfig
		if err := json.Unmarshal(bytes.TrimSpace(out), &cfg); err != nil {
			// log
			continue
		}
		n := strings.TrimPrefix(Pattern[:len(Pattern)-2], filepath.Base(x))

		var pv, pe, hdr bool
		for _, cap := range cfg.Capabilities {
			switch cap {
			case `parse_vulnerabilities`:
				pv = true
			case `parse_enrichments`:
				pe = true
			case `header_framing`:
				hdr = true
			}
		}
		switch {
		case pv && pe:
			set[n] = &dualUpdater{
				updater: updater{
					name:          n,
					path:          x,
					headerFraming: hdr,
				},
			}
		case pv && !pe:
			set[n] = &vulnerabilityUpdater{
				updater: updater{
					name:          n,
					path:          x,
					headerFraming: hdr,
				},
			}
		case !pv && pe:
			set[n] = &enrichmentUpdater{
				updater: updater{
					name:          n,
					path:          x,
					headerFraming: hdr,
				},
			}
		case !pv && !pe:
			// log, skip
		}
	}

	return set, nil
}

const Pattern = `clair-updater-*`

type FactoryConfig struct {
	Exec []string `json:"exec,omitempty" yaml:"exec,omitemtpy"`
}

type updater struct {
	name          string
	path          string
	headerFraming bool
}

func (u *updater) Name() string {
	return u.name
}

func (u *updater) Fetch(ctx context.Context, w *zip.Writer, fp driver.Fingerprint, c *http.Client) (driver.Fingerprint, error) {
	// todo...
	root, err := os.MkdirTemp(``, u.name+".*")
	if err != nil {
		return fp, err
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			zlog.Warn(ctx).Err(err).Msg("error removing temporary directory")
		}
	}()

	env := os.Environ()
	proxy, err := newProxy(ctx, c)
	if err != nil {
		return fp, err
	}
	defer proxy.Close()
	n := 0
	for _, e := range env {
		if false ||
			strings.HasPrefix(e, `http_proxy`) ||
			strings.HasPrefix(e, `HTTP_PROXY`) ||
			strings.HasPrefix(e, `https_proxy`) ||
			strings.HasPrefix(e, `HTTPS_PROXY`) {
			continue
		}
		env[n] = e
		n++
	}
	env = append(env, `http_proxy=`+proxy.Addr, `https_proxy=`+proxy.Addr)

	cmd := exec.Command(u.path, `v1`, `fetch`)
	cmd.Dir = root
	cmd.Env = env

	l := execListener(cmd)
	r := rpcv1Fetch{
		c:             c,
		async:         ctx,
		w:             w,
		prev:          fp,
		root:          root,
		headerFraming: u.headerFraming,
	}

	srv, err := jsonrpc2.Serve(ctx, l, &r)
	if err != nil {
		return fp, err
	}
	if err := srv.Wait(); err != nil {
		return fp, err
	}
	return r.ret, nil
}

func (u *updater) parseVulnerability(ctx context.Context, sys fs.FS) (*driver.ParsedVulnerabilities, error) {
	panic("TODO")
	// return nil, nil
}

func (u *updater) parseEnrichment(ctx context.Context, sys fs.FS) ([]driver.EnrichmentRecord, error) {
	panic("TODO")
	// return nil, nil
}

// The following types just promote the Parse methods.

type dualUpdater struct {
	updater
}

func (d *dualUpdater) ParseVulnerability(ctx context.Context, sys fs.FS) (*driver.ParsedVulnerabilities, error) {
	return d.parseVulnerability(ctx, sys)
}

func (d *dualUpdater) ParseEnrichment(ctx context.Context, sys fs.FS) ([]driver.EnrichmentRecord, error) {
	return d.parseEnrichment(ctx, sys)
}

type vulnerabilityUpdater struct {
	updater
}

func (v *vulnerabilityUpdater) ParseVulnerability(ctx context.Context, sys fs.FS) (*driver.ParsedVulnerabilities, error) {
	return v.parseVulnerability(ctx, sys)
}

type enrichmentUpdater struct {
	updater
}

func (e *enrichmentUpdater) ParseEnrichment(ctx context.Context, sys fs.FS) ([]driver.EnrichmentRecord, error) {
	return e.parseEnrichment(ctx, sys)
}
