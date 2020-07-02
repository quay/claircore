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
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/rhel/containerapi"
	"github.com/quay/claircore/rhel/contentmanifest"
)

// RepositoryScanner implements Red Hat Cpes based repositories
type RepositoryScanner struct {
	cpeAPIFetcher   *containerapi.ContainerAPI
	timeout         time.Duration
	contentmanifest *contentmanifest.RepoCPEMapping
}

// RepoScannerConfig is the struct that will be passed to
// (*RepositoryScanner).Configure's ConfigDeserializer argument.
type RepoScannerConfig struct {
	Timeout             time.Duration `json:"timeout",yaml:"timeout"`
	API                 string        `json:"api",yaml:"api"`
	Repo2CPEMappingPath string        `json:repo2cpe_mapping_path,yaml:"repo2cpe_mapping_path"`
	Repo2CPEMappingURL  string        `json:repo2cpe_mapping_url,yaml:"repo2cpe_mapping_url"`
}

// RedHatCPERepositoryKey is a key of Red Hat's CPE based repository
const RedHatCPERepositoryKey = "rhel-cpe-repo"

// Name implements scanner.Name.
func (*RepositoryScanner) Name() string { return "rhel-cpe-scanner" }

// Version implements scanner.VersionedScanner.
func (*RepositoryScanner) Version() string { return "1.0" }

// Kind implements scanner.VersionedScanner.
func (*RepositoryScanner) Kind() string { return "repository" }

// DefaultContainerAPI is a default Red Hat's container API URL
const DefaultContainerAPI = "https://catalog.redhat.com/api/containers/"

// DefaultRepo2CPEMapping is a default URL for mapping between repositories and CPEs
const DefaultRepo2CPEMapping = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"

// DefaultRepo2CPEMappingPath is a default local path where mapping file is stored
const DefaultRepo2CPEMappingPath = "/tmp/repository-2-cpe.json"

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
		cfg.API = DefaultContainerAPI
	}

	root, err := url.Parse(cfg.API)
	if err != nil {
		return err
	}
	if cfg.Repo2CPEMappingPath == "" {
		cfg.Repo2CPEMappingPath = DefaultRepo2CPEMappingPath
	}
	if cfg.Repo2CPEMappingURL == "" {
		cfg.Repo2CPEMappingURL = DefaultRepo2CPEMapping
	}
	r.contentmanifest = &contentmanifest.RepoCPEMapping{
		RepoCPEUpdater: contentmanifest.NewLocalUpdaterJob(
			cfg.Repo2CPEMappingPath,
			cfg.Repo2CPEMappingURL,
			c,
		),
	}

	r.cpeAPIFetcher = &containerapi.ContainerAPI{
		Root:   root,
		Client: c,
	}
	r.timeout = cfg.Timeout
	return nil
}

// Scan gets Red Hat repositories based on CPE information.
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

	cpes, err := r.contentSets(ctx, &log, l)
	if err != nil {
		return []*claircore.Repository{}, err
	}
	if cpes == nil && r.cpeAPIFetcher != nil {
		// Embedded content-sets are available only for new images.
		// For old images, use fallback option and query Red Hat Container API.
		ctx, done := context.WithTimeout(ctx, r.timeout)
		defer done()
		cpes, err = r.containerAPI(ctx, &log, l)
		if err != nil {
			return []*claircore.Repository{}, err
		}
	}

	for _, n := range cpes {
		r := &claircore.Repository{
			Name: n,
			Key:  RedHatCPERepositoryKey,
		}
		r.CPE, err = cpe.Unbind(n)
		if err != nil {
			return nil, err
		}

		repositories = append(repositories, r)
	}

	return repositories, nil
}

// ContentSets returns a slice of CPEs bound into strings, as discovered by
// examining information contained within the container.
func (r *RepositoryScanner) contentSets(ctx context.Context, log *zerolog.Logger, l *claircore.Layer) ([]string, error) {
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
	cpes, err := r.contentmanifest.RepositoryToCPE(ctx, contentManifestData.ContentSets)
	return cpes, err
}

func (r *RepositoryScanner) containerAPI(ctx context.Context, log *zerolog.Logger, l *claircore.Layer) ([]string, error) {
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

	cpes, err := r.cpeAPIFetcher.GetCPEs(ctx, nvr, arch)
	log.Debug().
		Str("nvr", nvr).
		Str("arch", arch).
		Strs("CPEs", cpes).
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
