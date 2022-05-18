package rhcc

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/rhel/dockerfile"
)

var _ indexer.PackageScanner = (*scanner)(nil)

type nameReposMapper interface {
	Get(context.Context, *http.Client, string) []string
}

type scanner struct {
	mapper nameReposMapper
	client *http.Client
	cfg    ScannerConfig
}

type ScannerConfig struct {
	Name2ReposMappingURL  string        `json:"name2repos_mapping_url" yaml:"name2repos_mapping_url"`
	Name2ReposMappingFile string        `json:"name2repos_mapping_file" yaml:"name2repos_mapping_file"`
	Timeout               time.Duration `json:"timeout" yaml:"timeout"`
}

// DefaultRepo2CPEMappingURL is default URL with a mapping file provided by Red
// Hat.
const DefaultName2ReposMappingURL = "https://access.redhat.com/security/data/metrics/container-name-repos-map.json"

// Configure implements the RPCScanner interface.
func (s *scanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/scanner.Configure")
	s.client = c
	if err := f(&s.cfg); err != nil {
		return err
	}
	// Set defaults if not set via passed function.
	switch {
	case s.cfg.Name2ReposMappingURL == "" && s.cfg.Name2ReposMappingFile == "":
		// defaults
		s.cfg.Name2ReposMappingURL = DefaultName2ReposMappingURL
		fallthrough
	case s.cfg.Name2ReposMappingURL != "" && s.cfg.Name2ReposMappingFile == "":
		// remote only
		u := newUpdatingMapper(s.cfg.Name2ReposMappingURL, nil)
		if err := u.Fetch(ctx, s.client); err != nil {
			return err
		}
		s.mapper = u
	case s.cfg.Name2ReposMappingURL == "" && s.cfg.Name2ReposMappingFile != "":
		// local only
		f, err := os.Open(s.cfg.Name2ReposMappingFile)
		if err != nil {
			return err
		}
		defer f.Close()
		var mf mappingFile
		if err := json.NewDecoder(f).Decode(&mf); err != nil {
			return err
		}
		s.mapper = &mf
	case s.cfg.Name2ReposMappingURL != "" && s.cfg.Name2ReposMappingFile != "":
		// load, then fetch later
		f, err := os.Open(s.cfg.Name2ReposMappingFile)
		if err != nil {
			return err
		}
		defer f.Close()
		var mf mappingFile
		if err := json.NewDecoder(f).Decode(&mf); err != nil {
			return err
		}
		s.mapper = newUpdatingMapper(s.cfg.Name2ReposMappingURL, &mf)
	}
	if s.cfg.Timeout == 0 {
		s.cfg.Timeout = 30 * time.Second
	}
	return nil
}

func (s *scanner) Name() string { return "rhel_containerscanner" }

func (s *scanner) Version() string { return "1" }

func (s *scanner) Kind() string { return "package" }

// Scan performs a package scan on the given layer and returns all
// the RHEL container identifying metadata
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

	// add source package from component label
	labels, p, err := findLabels(ctx, l)
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

	repos := s.mapper.Get(ctx, s.client, name)
	if len(repos) == 0 {
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

func findLabels(ctx context.Context, layer *claircore.Layer) (map[string]string, string, error) {
	r, err := layer.Reader()
	if err != nil {
		return nil, "", err
	}
	defer r.Close()
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, "", err
	}
	ms, err := fs.Glob(sys, "root/buildinfo/Dockerfile-*")
	if err != nil { // Can only return ErrBadPattern.
		panic("progammer error")
	}
	if len(ms) == 0 {
		return nil, "", errNotFound
	}
	p := ms[0]
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

var errNotFound = errors.New("not found")

// GetVR extracts the version-release string from the provided string ending in
// an NVR.
//
// Panics if passed malformed input.
func getVR(nvr string) string {
	if strings.Count(nvr, "-") < 2 {
		panic("programmer error")
	}
	i := strings.LastIndexByte(nvr, '-')
	i = strings.LastIndexByte(nvr[:i], '-')
	return nvr[i+1:]
}

type reposcanner struct{}

var _ indexer.RepositoryScanner = (*reposcanner)(nil)

func (s *reposcanner) Name() string { return "rhel_containerscanner" }

func (s *reposcanner) Version() string { return "1" }

func (s *reposcanner) Kind() string { return "repository" }

func (s *reposcanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Repository, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/reposcanner.Scan")
	r, err := l.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	sys, err := tarfs.New(r)
	if err != nil {
		return nil, err
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
	return []*claircore.Repository{&goldRepo}, nil
}
