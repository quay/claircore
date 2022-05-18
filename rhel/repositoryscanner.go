package rhel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/trace"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/rhel/containerapi"
	"github.com/quay/claircore/rhel/contentmanifest"
	"github.com/quay/claircore/rhel/dockerfile"
	"github.com/quay/claircore/rhel/repo2cpe"
)

// RepoCPEUpdater provides interface for providing a mapping
// between repositories and CPEs
type repoCPEMapper interface {
	Get(context.Context, []string) ([]string, error)
}

// RepositoryScanner implements Red Hat repositories
type RepositoryScanner struct {
	cfg RepoScannerConfig

	// These members are created after the Configure call.
	apiFetcher *containerapi.ContainerAPI
	mapper     repoCPEMapper
	client     *http.Client
}

// RepoScannerConfig is the struct that will be passed to
// (*RepositoryScanner).Configure's ConfigDeserializer argument.
type RepoScannerConfig struct {
	Timeout             time.Duration `json:"timeout" yaml:"timeout"`
	API                 string        `json:"api" yaml:"api"`
	Repo2CPEMappingURL  string        `json:"repo2cpe_mapping_url" yaml:"repo2cpe_mapping_url"`
	Repo2CPEMappingFile string        `json:"repo2cpe_mapping_file" yaml:"repo2cpe_mapping_file"`
}

// RedHatRepositoryKey is a key of Red Hat's CPE based repository
const RedHatRepositoryKey = "rhel-cpe-repository"

// Name implements scanner.Name.
func (*RepositoryScanner) Name() string { return "rhel-repository-scanner" }

// Version implements scanner.VersionedScanner.
func (*RepositoryScanner) Version() string { return "1.1" }

// Kind implements scanner.VersionedScanner.
func (*RepositoryScanner) Kind() string { return "repository" }

// DefaultContainerAPI is a default Red Hat's container API URL
const DefaultContainerAPI = "https://catalog.redhat.com/api/containers/"

// DefaultRepo2CPEMappingURL is default URL with a mapping file provided by Red Hat
const DefaultRepo2CPEMappingURL = "https://access.redhat.com/security/data/metrics/repository-to-cpe.json"

// NewRepositoryScanner create new Repo scanner struct and initialize mapping updater
func NewRepositoryScanner(ctx context.Context, c *http.Client, cs2cpeURL string) *RepositoryScanner {
	scanner := &RepositoryScanner{}
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/NewRepositoryScanner",
		"version", scanner.Version())

	scanner.client = c
	return scanner
}

// Configure implements the RPCScanner interface.
func (r *RepositoryScanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/RepositoryScanner.Configure",
		"version", r.Version())
	r.client = c
	if err := f(&r.cfg); err != nil {
		return err
	}
	// Set defaults if not set via passed function.
	if r.cfg.API == "" {
		const name = `CONTAINER_API_URL`
		r.cfg.API = DefaultContainerAPI
		if env := os.Getenv(name); env != "" {
			zlog.Warn(ctx).
				Str("name", name).
				Msg("this environment variable will be ignored in the future, use the configuration")
			r.cfg.API = env
		}
	}
	if r.cfg.Timeout == 0 {
		r.cfg.Timeout = 30 * time.Second
	}

	switch {
	case r.cfg.Repo2CPEMappingURL == "" && r.cfg.Repo2CPEMappingFile == "":
		// defaults
		const name = `REPO_TO_CPE_URL`
		r.cfg.Repo2CPEMappingURL = DefaultRepo2CPEMappingURL
		if env := os.Getenv(name); env != "" {
			zlog.Warn(ctx).
				Str("name", name).
				Msg("this environment variable will be ignored in the future, use the configuration")
			r.cfg.Repo2CPEMappingURL = env
		}
		fallthrough
	case r.cfg.Repo2CPEMappingURL != "" && r.cfg.Repo2CPEMappingFile == "":
		// remote only
		u := repo2cpe.NewUpdatingMapper(r.client, r.cfg.Repo2CPEMappingURL, nil)
		if err := u.Fetch(ctx); err != nil {
			return err
		}
		r.mapper = u
	case r.cfg.Repo2CPEMappingURL == "" && r.cfg.Repo2CPEMappingFile != "":
		// local only
		f, err := os.Open(r.cfg.Repo2CPEMappingFile)
		if err != nil {
			return err
		}
		defer f.Close()
		var mf repo2cpe.MappingFile
		if err := json.NewDecoder(f).Decode(&mf); err != nil {
			return err
		}
		r.mapper = &mf
	case r.cfg.Repo2CPEMappingURL != "" && r.cfg.Repo2CPEMappingFile != "":
		// load, then fetch later
		f, err := os.Open(r.cfg.Repo2CPEMappingFile)
		if err != nil {
			return err
		}
		defer f.Close()
		var mf repo2cpe.MappingFile
		if err := json.NewDecoder(f).Decode(&mf); err != nil {
			return err
		}
		r.mapper = repo2cpe.NewUpdatingMapper(r.client, r.cfg.Repo2CPEMappingURL, &mf)
	}

	// Additional setup
	root, err := url.Parse(r.cfg.API)
	if err != nil {
		return err
	}

	r.apiFetcher = &containerapi.ContainerAPI{
		Root:   root,
		Client: r.client,
	}

	return nil
}

// Scan gets Red Hat repositories information.
func (r *RepositoryScanner) Scan(ctx context.Context, l *claircore.Layer) (repositories []*claircore.Repository, err error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/RepositoryScanner.Scan",
		"version", r.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	rd, err := l.Reader()
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open layer: %w", err)
	}
	defer rd.Close()
	sys, err := tarfs.New(rd)
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open layer: %w", err)
	}

	CPEs, err := r.getCPEsUsingEmbeddedContentSets(ctx, sys)
	if err != nil {
		return []*claircore.Repository{}, err
	}
	if CPEs == nil && r.apiFetcher != nil {
		// Embedded content-sets are available only for new images.
		// For old images, use fallback option and query Red Hat Container API.
		ctx, done := context.WithTimeout(ctx, r.cfg.Timeout)
		defer done()
		CPEs, err = r.getCPEsUsingContainerAPI(ctx, sys)
		if err != nil {
			return []*claircore.Repository{}, err
		}
	}

	for _, cpeID := range CPEs {
		r := &claircore.Repository{
			Name: cpeID,
			Key:  RedHatRepositoryKey,
		}
		r.CPE, err = cpe.Unbind(cpeID)
		if err != nil {
			zlog.Warn(ctx).
				Err(err).
				Str("url", `https://bugzilla.redhat.com/enter_bug.cgi?product=Container%20Factory`).
				Str("cpeID", cpeID).
				Msg("invalid CPE, please report a bug upstream")
			continue
		}

		repositories = append(repositories, r)
	}

	return repositories, nil
}

// getCPEsUsingEmbeddedContentSets returns a slice of CPEs bound into strings, as discovered by
// examining information contained within the container.
func (r *RepositoryScanner) getCPEsUsingEmbeddedContentSets(ctx context.Context, sys fs.FS) ([]string, error) {
	// Get CPEs using embedded content-set files.
	// The files is be stored in /root/buildinfo/content_manifests/ and will need to
	// be translated using mapping file provided by Red Hat's PST team.
	ms, err := fs.Glob(sys, `root/buildinfo/content_manifests/*.json`)
	if err != nil {
		panic(fmt.Errorf("programmer error: %w", err))
	}
	if ms == nil {
		return nil, nil
	}
	p := ms[0]
	zlog.Debug(ctx).
		Str("manifest-path", p).
		Msg("found content manifest file")
	b, err := fs.ReadFile(sys, p)
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to read %q: %w", p, err)
	}
	var m contentmanifest.ContentManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return r.mapper.Get(ctx, m.ContentSets)
}

func (r *RepositoryScanner) getCPEsUsingContainerAPI(ctx context.Context, sys fs.FS) ([]string, error) {
	ms, err := fs.Glob(sys, "root/buildinfo/Dockerfile-*")
	if err != nil {
		panic(fmt.Errorf("programmer error: %w", err))
	}
	if ms == nil {
		return nil, nil
	}
	p := ms[0]
	b, err := fs.ReadFile(sys, p)
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to read %q: %w", p, err)
	}

	nvr, arch, err := extractBuildNVR(ctx, p, b)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errBadDockerfile):
		zlog.Info(ctx).
			AnErr("label_error", err).
			Msg("bad dockerfile")
		return nil, nil
	default:
		return nil, err
	}

	cpes, err := r.apiFetcher.GetCPEs(ctx, nvr, arch)
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Str("nvr", nvr).
		Str("arch", arch).
		Strs("cpes", cpes).
		Msg("Got CPEs from container API")
	return cpes, nil
}

// extractBuildNVR - extract build NVR (name-version-release) from Dockerfile
// stored in filesystem
// The redhat.com.component LABEL is extracted from dockerfile and it is used as name
// Version and release is extracted from Dockerfile name
// Arch is extracted from 'architecture' LABEL
func extractBuildNVR(ctx context.Context, dockerfilePath string, b []byte) (string, string, error) {
	const (
		comp = `com.redhat.component`
		arch = `architecture`
	)
	ls, err := dockerfile.GetLabels(ctx, bytes.NewReader(b))
	if err != nil {
		return "", "", err
	}
	n, ok := ls[comp]
	if !ok {
		return "", "", missingLabel(comp)
	}
	a, ok := ls[arch]
	if !ok {
		return "", "", missingLabel(arch)
	}
	v, r := parseVersionRelease(filepath.Base(dockerfilePath))
	return fmt.Sprintf("%s-%s-%s", n, v, r), a, nil
}

var errBadDockerfile = errors.New("bad dockerfile")

type missingLabel string

func (e missingLabel) Error() string {
	return fmt.Sprintf("dockerfile missing expected label %q", string(e))
}

func (e missingLabel) Is(tgt error) bool {
	if oe, ok := tgt.(missingLabel); ok {
		return string(oe) == string(e)
	}
	return errors.Is(tgt, errBadDockerfile)
}

// parseVersionRelease - parse release and version from NVR
func parseVersionRelease(nvr string) (version, release string) {
	releaseIndex := strings.LastIndex(nvr, "-")
	release = nvr[releaseIndex+1:]

	versionIndex := strings.LastIndex(nvr[:releaseIndex], "-")
	version = nvr[versionIndex+1 : releaseIndex]
	return
}
