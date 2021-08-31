package rhel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/trace"
	"strings"
	"time"

	"github.com/docker-slim/docker-slim/pkg/docker/dockerfile/ast"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/rhel/containerapi"
	"github.com/quay/claircore/rhel/contentmanifest"
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "rhel/NewRepositoryScanner"),
		label.String("version", scanner.Version()))

	scanner.client = c
	return scanner
}

// Configure implements the RPCScanner interface.
func (r *RepositoryScanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "rhel/RepositoryScanner.Configure"),
		label.String("version", r.Version()))
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
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "rhel/RepositoryScanner.Scan"),
		label.String("version", r.Version()),
		label.Stringer("layer", l.Hash))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	CPEs, err := r.getCPEsUsingEmbeddedContentSets(ctx, l)
	if err != nil {
		return []*claircore.Repository{}, err
	}
	if CPEs == nil && r.apiFetcher != nil {
		// Embedded content-sets are available only for new images.
		// For old images, use fallback option and query Red Hat Container API.
		ctx, done := context.WithTimeout(ctx, r.cfg.Timeout)
		defer done()
		CPEs, err = r.getCPEsUsingContainerAPI(ctx, l)
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
			return nil, err
		}

		repositories = append(repositories, r)
	}

	return repositories, nil
}

// getCPEsUsingEmbeddedContentSets returns a slice of CPEs bound into strings, as discovered by
// examining information contained within the container.
func (r *RepositoryScanner) getCPEsUsingEmbeddedContentSets(ctx context.Context, l *claircore.Layer) ([]string, error) {
	// Get CPEs using embedded content-set files.
	// The files is be stored in /root/buildinfo/content_manifests/ and will need to
	// be translated using mapping file provided by Red Hat's PST team.
	path, buf, err := findContentManifestFile(l)
	switch {
	case err == nil:
	case buf == nil:
		fallthrough
	case errors.Is(err, claircore.ErrNotFound):
		return nil, nil
	default:
		return nil, err
	}
	zlog.Debug(ctx).
		Str("manifest-path", path).
		Msg("found content manifest file")
	contentManifestData := contentmanifest.ContentManifest{}
	err = json.NewDecoder(buf).Decode(&contentManifestData)
	if err != nil {
		return nil, err
	}
	return r.mapper.Get(ctx, contentManifestData.ContentSets)
}

func (r *RepositoryScanner) getCPEsUsingContainerAPI(ctx context.Context, l *claircore.Layer) ([]string, error) {
	path, buf, err := findDockerfile(l)
	switch {
	case err == nil:
	case buf == nil:
		fallthrough
	case errors.Is(err, claircore.ErrNotFound):
		return nil, nil
	default:
		return nil, err
	}

	nvr, arch, err := extractBuildNVR(path, buf)
	if err != nil {
		return nil, err
	}
	if nvr == "" || arch == "" {
		return nil, nil
	}

	cpes, err := r.apiFetcher.GetCPEs(ctx, nvr, arch)
	zlog.Debug(ctx).
		Str("nvr", nvr).
		Str("arch", arch).
		Strs("cpes", cpes).
		Msg("Got CPEs from container API")
	if err != nil {
		return nil, err
	}
	return cpes, nil
}

func findContentManifestFile(l *claircore.Layer) (string, *bytes.Buffer, error) {
	re, err := regexp.Compile(`^root/buildinfo/content_manifests/.*\.json`)
	if err != nil {
		return "", nil, err
	}
	files, err := filesByRegexp(l, re)
	if err != nil {
		return "", nil, err
	}
	// there should be always just one content manifest file - return the first from a map
	for name, buf := range files {
		return name, buf, nil
	}
	return "", nil, nil
}

// FindDockerfile finds a Dockerfile in layer tarball and returns its name and
// content.
func findDockerfile(l *claircore.Layer) (string, *bytes.Buffer, error) {
	// Dockerfile which was used to build given image/layer is stored by OSBS in /root/buildinfo/
	// Name of dockerfiles is in following format "Dockerfile-NAME-VERSION-RELEASE"
	// Name, version and release are labels defined in the dockerfile
	re, err := regexp.Compile("root/buildinfo/Dockerfile-.*")
	if err != nil {
		return "", nil, err
	}
	files, err := filesByRegexp(l, re)
	if err != nil {
		return "", nil, err
	}
	// there should be always just one Dockerfile - return the first from a map
	for name, buf := range files {
		return name, buf, nil
	}
	return "", nil, nil
}

// extractBuildNVR - extract build NVR (name-version-release) from Dockerfile
// stored in filesystem
// The redhat.com.component LABEL is extracted from dockerfile and it is used as name
// Version and release is extracted from Dockerfile name
// Arch is extracted from 'architecture' LABEL
func extractBuildNVR(dockerfilePath string, buf *bytes.Buffer) (string, string, error) {
	res, err := ast.Parse(buf)
	if err != nil {
		return "", "", err
	}

	if !res.AST.IsValid {
		return "", "", fmt.Errorf("rhel: invalid Dockerfile at %q", dockerfilePath)
	}
	vm := map[string]string{}
	for _, node := range res.AST.Children {
		cmd := node.Value
		if cmd != "env" && cmd != "arg" {
			continue
		}
		var args []string
		for n := node.Next; n != nil; n = n.Next {
			args = append(args, n.Value)
		}
		switch cmd {
		case "arg":
			for _, arg := range args {
				if strings.Contains(arg, "=") {
					pair := strings.SplitN(arg, "=", 2)
					vm[pair[0]] = pair[1]
				} else {
					vm[arg] = ""
				}
			}
		case "env":
			if len(args)%2 != 0 {
				return "", "", errors.New("dockerfile botch")
			}
			for i := 0; i < len(args); i += 2 {
				if args[i] == "" {
					continue
				}
				vm[args[i]] = args[i+1]
			}
		}
	}
	expand := func(v string) string {
		return vm[v]
	}

	var name, arch string
	for _, node := range res.AST.Children {
		cmd := node.Value
		if cmd != "label" {
			continue
		}
		var args []string
		for n := node.Next; n != nil; n = n.Next {
			args = append(args, n.Value)
		}
		for i, v := range args {
			switch strings.Trim(v, "\"") {
			case "com.redhat.component":
				name = strings.Trim(args[i+1], "\"")
				name = os.Expand(name, expand)
			case "architecture":
				arch = strings.Trim(args[i+1], "\"")
				arch = os.Expand(arch, expand)
			}
		}
	}

	version, release := parseVersionRelease(filepath.Base(dockerfilePath))
	return fmt.Sprintf("%s-%s-%s", name, version, release), arch, nil
}

// parseVersionRelease - parse release and version from NVR
func parseVersionRelease(nvr string) (version, release string) {
	releaseIndex := strings.LastIndex(nvr, "-")
	release = nvr[releaseIndex+1:]

	versionIndex := strings.LastIndex(nvr[:releaseIndex], "-")
	version = nvr[versionIndex+1 : releaseIndex]
	return
}
