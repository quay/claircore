package rhcc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/zreader"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/rhel/dockerfile"
	"github.com/quay/claircore/rhel/internal/common"
)

var (
	_ indexer.PackageScanner = (*scanner)(nil)
	_ indexer.RPCScanner     = (*scanner)(nil)
)

// Deprecated: scanner will be removed in a future releases as Red Hat images
// produced from the legacy build system stop being produced / supported.
type scanner struct {
	upd    *common.Updater
	client *http.Client
	cfg    ScannerConfig
}

// ScannerConfig is the configuration for the package scanner.
//
// The interaction between the "URL" and "File" members is the same as described
// in the [github.com/quay/claircore/rhel.RepositoryScannerConfig] documentation.
//
// By convention, it's in a "rhel_containerscanner" key.
type ScannerConfig struct {
	// Name2ReposMappingURL is a URL where a mapping file can be fetched.
	//
	// See also [DefaultName2ReposMappingURL]
	Name2ReposMappingURL string `json:"name2repos_mapping_url" yaml:"name2repos_mapping_url"`
	// Name2ReposMappingFile is a path to a local mapping file.
	Name2ReposMappingFile string `json:"name2repos_mapping_file" yaml:"name2repos_mapping_file"`
	// Timeout is a timeout for all network calls made to update the mapping
	// file.
	//
	// The default is 10 seconds.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
}

// DefaultName2ReposMappingURL is the default URL with a mapping file provided by Red
// Hat.
//
//doc:url indexer
const DefaultName2ReposMappingURL = "https://security.access.redhat.com/data/metrics/container-name-repos-map.json"

// Configure implements [indexer.RPCScanner].
func (s *scanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/scanner.Configure")
	s.client = c
	if err := f(&s.cfg); err != nil {
		return err
	}

	if s.cfg.Timeout == 0 {
		s.cfg.Timeout = 10 * time.Second
	}
	var mf *mappingFile
	switch {
	case s.cfg.Name2ReposMappingURL == "" && s.cfg.Name2ReposMappingFile == "":
		// defaults
		s.cfg.Name2ReposMappingURL = DefaultName2ReposMappingURL
	case s.cfg.Name2ReposMappingURL != "" && s.cfg.Name2ReposMappingFile == "":
		// remote only
	case s.cfg.Name2ReposMappingFile != "":
		// local only
		f, err := os.Open(s.cfg.Name2ReposMappingFile)
		if err != nil {
			return err
		}
		defer f.Close()
		z, err := zreader.Reader(f)
		if err != nil {
			return err
		}
		defer z.Close()
		mf = &mappingFile{}
		if err := json.NewDecoder(z).Decode(mf); err != nil {
			return err
		}
	}
	s.upd = common.NewUpdater(s.cfg.Name2ReposMappingURL, mf)
	tctx, done := context.WithTimeout(ctx, s.cfg.Timeout)
	defer done()
	s.upd.Get(tctx, c)

	return nil
}

// Name implements [indexer.VersionedScanner].
func (s *scanner) Name() string { return "rhel_containerscanner" }

// Version implements [indexer.VersionedScanner].
func (s *scanner) Version() string { return "1" }

// Kind implements [indexer.VersionedScanner].
func (s *scanner) Kind() string { return "package" }

// Scan performs a package scan on the given layer and returns all
// the RHEL container identifying metadata

// Scan implements [indexer.PackageScanner].
func (s *scanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Package, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/scanner.Scan")
	const (
		compLabel = `com.redhat.component`
		nameLabel = `name`
		archLabel = `architecture`
	)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to open layer: %w", err)
	}

	// add source package from component label
	labels, p, err := findLabels(ctx, sys)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errNotFound):
		return nil, nil
	default:
		return nil, err
	}

	vr := getVR(p)
	rhctagVersion, err := rhctag.Parse(vr)
	if err != nil {
		// This can happen for containers which don't use semantic versioning,
		// such as UBI.
		return nil, nil
	}
	var buildName, arch, name string
	for _, chk := range []struct {
		Found *string
		Want  string
	}{
		{&buildName, compLabel},
		{&arch, archLabel},
		{&name, nameLabel},
	} {
		var ok bool
		(*chk.Found), ok = labels[chk.Want]
		if !ok {
			zlog.Info(ctx).Str("label", chk.Want).Msg("expected label not found in dockerfile")
			return nil, nil
		}
	}

	minorRange := rhctagVersion.MinorStart()
	src := claircore.Package{
		Kind:              claircore.SOURCE,
		Name:              buildName,
		Version:           vr,
		NormalizedVersion: minorRange.Version(true),
		PackageDB:         p,
		Arch:              arch,
		RepositoryHint:    `rhcc`,
	}
	pkgs := []*claircore.Package{&src}

	tctx, done := context.WithTimeout(ctx, s.cfg.Timeout)
	defer done()
	vi, err := s.upd.Get(tctx, s.client)
	if err != nil && vi == nil {
		return nil, err
	}
	v, ok := vi.(*mappingFile)
	if !ok || v == nil {
		return nil, fmt.Errorf("rhcc: unable to create a mappingFile object")
	}
	repos, ok := v.Data[name]
	if ok {
		zlog.Debug(ctx).Str("name", name).
			Msg("name present in mapping file")
	} else {
		// Didn't find external_repos in mapping, use name label as package
		// name.
		repos = []string{name}
	}
	for _, name := range repos {
		// Add each external repo as a binary package. The same container image
		// can ship to multiple repos eg. `"toolbox-container":
		// ["rhel8/toolbox", "ubi8/toolbox"]`. Therefore, we want a binary
		// package entry for each.
		pkgs = append(pkgs, &claircore.Package{
			Kind:              claircore.BINARY,
			Name:              name,
			Version:           vr,
			NormalizedVersion: minorRange.Version(true),
			Source:            &src,
			PackageDB:         p,
			Arch:              arch,
			RepositoryHint:    `rhcc`,
		})
	}
	return pkgs, nil
}

// MappingFile is a struct for mapping file between container NAME label and
// container registry repository location.
type mappingFile struct {
	Data map[string][]string `json:"data"`
}

func findLabels(ctx context.Context, sys fs.FS) (map[string]string, string, error) {
	ms, err := fs.Glob(sys, "root/buildinfo/Dockerfile-*")
	if err != nil { // Can only return ErrBadPattern.
		panic("progammer error: " + err.Error())
	}
	if len(ms) == 0 {
		return nil, "", errNotFound
	}
	zlog.Debug(ctx).
		Strs("paths", ms).
		Msg("found possible buildinfo Dockerfile(s)")
	var p string
	for _, m := range ms {
		if strings.Count(m, "-") > 1 {
			p = m
			break
		}
	}
	if p == "" {
		return nil, "", errNotFound
	}
	zlog.Info(ctx).
		Str("path", p).
		Msg("found buildinfo Dockerfile")
	f, err := sys.Open(p)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	labels, err := dockerfile.GetLabels(ctx, f)
	if err != nil {
		return nil, "", err
	}
	return labels, p, nil
}

// GetVR extracts the version-release string from the provided string ending in
// an NVR.
//
// Panics if passed malformed input.
func getVR(nvr string) string {
	if strings.Count(nvr, "-") < 2 {
		panic("programmer error: not an nvr string: " + nvr)
	}
	i := strings.LastIndexByte(nvr, '-')
	i = strings.LastIndexByte(nvr[:i], '-')
	return nvr[i+1:]
}

// Deprecated: reposcanner will be removed in a future releases as Red Hat images
// produced from the legacy build system stop being produced / supported.
type reposcanner struct{}

var _ indexer.RepositoryScanner = (*reposcanner)(nil)

// Name implements [indexer.VersionedScanner].
func (s *reposcanner) Name() string { return "rhel_containerscanner" }

// Version implements [indexer.VersionedScanner].
func (s *reposcanner) Version() string { return "1" }

// Kind implements [indexer.VersionedScanner].
func (s *reposcanner) Kind() string { return "repository" }

// Scan implements [indexer.RepositoryScanner].
func (s *reposcanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Repository, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/reposcanner.Scan")
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to open layer: %w", err)
	}
	ms, err := fs.Glob(sys, "root/buildinfo/Dockerfile-*")
	if err != nil { // Can only return ErrBadPattern.
		panic("progammer error")
	}
	if len(ms) == 0 {
		return nil, nil
	}
	zlog.Debug(ctx).
		Msg("found buildinfo Dockerfile")
	return []*claircore.Repository{&GoldRepo}, nil
}
