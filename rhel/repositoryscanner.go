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
	"sync"
	"time"

	"github.com/docker-slim/docker-slim/pkg/docker/dockerfile/ast"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/rhel/containerapi"
	"github.com/quay/claircore/rhel/contentmanifest"
	"github.com/quay/claircore/rhel/repo2cpe"
)

// RepositoryScanner implements Red Hat repositories
type RepositoryScanner struct {
	apiFetcher *containerapi.ContainerAPI
	mapping    *repo2cpe.RepoCPEMapping
	timeout    time.Duration
}

// RepoScannerConfig is the struct that will be passed to
// (*RepositoryScanner).Configure's ConfigDeserializer argument.
type RepoScannerConfig struct {
	Timeout            time.Duration `json:"timeout" yaml:"timeout"`
	API                string        `json:"api" yaml:"api"`
	Repo2CPEMappingURL string        `json:"repo2cpe_mapping_url" yaml:"repo2cpe_mapping_url"`
}

// RedHatRepositoryKey is a key of Red Hat's CPE based repository
const RedHatRepositoryKey = "rhel-cpe-repository"

// Name implements scanner.Name.
func (*RepositoryScanner) Name() string { return "rhel-repository-scanner" }

// Version implements scanner.VersionedScanner.
func (*RepositoryScanner) Version() string { return "1.0" }

// Kind implements scanner.VersionedScanner.
func (*RepositoryScanner) Kind() string { return "repository" }

// DefaultContainerAPI is a default Red Hat's container API URL
const DefaultContainerAPI = "https://catalog.redhat.com/api/containers/"

// DefaultRepo2CPEMappingURL is default URL with a mapping file provided by Red Hat
const DefaultRepo2CPEMappingURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"

var localUpdater struct {
	once sync.Once
	u    repo2cpe.RepoCPEUpdater
}

// NewRepositoryScanner create new Repo scanner struct and initialize mapping updater
func NewRepositoryScanner(ctx context.Context, c *http.Client, cs2cpeURL string) *RepositoryScanner {
	scanner := &RepositoryScanner{}
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/RepositoryScanner/NewRepositoryScanner").
		Str("version", scanner.Version()).
		Logger()

	// initialize local updater for repository scanner if not done before.
	localUpdater.once.Do(
		func() {
			log.Debug().Msg("initializing local updater job. this log should only be seen once.")
			// TODO (araszka): replace it with config value when it will
			// be possible to store these values in config
			if cs2cpeURL == "" {
				cs2cpeURL = os.Getenv("REPO_TO_CPE_URL")
				if cs2cpeURL == "" {
					cs2cpeURL = DefaultRepo2CPEMappingURL
				}
			}
			u := repo2cpe.NewLocalUpdaterJob(cs2cpeURL, nil)
			u.Start(context.TODO())
			localUpdater.u = u
		})

	if c == nil {
		c = http.DefaultClient
	}
	scanner.mapping = &repo2cpe.RepoCPEMapping{
		RepoCPEUpdater: localUpdater.u,
	}
	return scanner
}

// Configure implements the RPCScanner interface.
func (r *RepositoryScanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	cfg := RepoScannerConfig{}
	if err := f(&cfg); err != nil {
		return err
	}
	// Set defaults if not set via passed function.
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.API == "" {
		// TODO (araszka): replace it with config value when it will
		// be possible to store these values in config
		cfg.API = os.Getenv("CONTAINER_API_URL")
		if cfg.API == "" {
			cfg.API = DefaultContainerAPI
		}
	}

	root, err := url.Parse(cfg.API)
	if err != nil {
		return err
	}

	r.apiFetcher = &containerapi.ContainerAPI{
		Root:   root,
		Client: c,
	}
	r.timeout = cfg.Timeout
	return nil
}

// Scan gets Red Hat repositories information.
func (r *RepositoryScanner) Scan(ctx context.Context, l *claircore.Layer) (repositories []*claircore.Repository, err error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/RepositoryScanner.Scan").
		Str("version", r.Version()).
		Str("layer", l.Hash.String()).
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")

	CPEs, err := r.getCPEsUsingEmbeddedContentSets(ctx, &log, l)
	if err != nil {
		return []*claircore.Repository{}, err
	}
	if CPEs == nil && r.apiFetcher != nil {
		// Embedded content-sets are available only for new images.
		// For old images, use fallback option and query Red Hat Container API.
		ctx, done := context.WithTimeout(ctx, r.timeout)
		defer done()
		CPEs, err = r.getCPEsUsingContainerAPI(ctx, &log, l)
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
func (r *RepositoryScanner) getCPEsUsingEmbeddedContentSets(ctx context.Context, log *zerolog.Logger, l *claircore.Layer) ([]string, error) {
	// Get CPEs using embedded content-set files.
	// The files is be stored in /root/buildinfo/content_manifests/ and will need to
	// be translated using mapping file provided by Red Hat's PST team.
	path, buf, err := findContentManifestFile(log, l)
	switch {
	case err == nil:
	case buf == nil:
		fallthrough
	case errors.Is(err, claircore.ErrNotFound):
		return nil, nil
	default:
		return nil, err
	}
	log.Debug().Str("manifest-path", path).Msg("Found content manifest file")
	contentManifestData := contentmanifest.ContentManifest{}
	err = json.NewDecoder(buf).Decode(&contentManifestData)
	if err != nil {
		return nil, err
	}
	return r.mapping.RepositoryToCPE(ctx, contentManifestData.ContentSets)
}

func (r *RepositoryScanner) getCPEsUsingContainerAPI(ctx context.Context, log *zerolog.Logger, l *claircore.Layer) ([]string, error) {
	path, buf, err := findDockerfile(log, l)
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
	log.Debug().
		Str("nvr", nvr).
		Str("arch", arch).
		Strs("cpes", cpes).
		Msg("Got CPEs from container API")
	if err != nil {
		return nil, err
	}
	return cpes, nil
}

func findContentManifestFile(log *zerolog.Logger, l *claircore.Layer) (string, *bytes.Buffer, error) {
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
func findDockerfile(log *zerolog.Logger, l *claircore.Layer) (string, *bytes.Buffer, error) {
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
