package rhel

import (
	"bytes"
	"context"
	"path/filepath"
	"runtime/trace"
	"strings"

	"github.com/asottile/dockerfile"
	"github.com/buildkite/interpolate"
	"github.com/quay/claircore"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// CpeFetcher is a interface for CPE remote fetcher
type CpeFetcher interface {
	GetCPEs(nvr, arch string) ([]string, error)
}

// RepositoryScanner implements Red Hat Cpes based repositories
type RepositoryScanner struct {
	CpeFetcher CpeFetcher
}

// RedHatCPERepositoryKey is a key of Red Hat's CPE based repository
const RedHatCPERepositoryKey = "rhel-cpe-repo"

// Name implements scanner.Name.
func (*RepositoryScanner) Name() string { return "rhel-cpe-scanner" }

// Version implements scanner.VersionedScanner.
func (*RepositoryScanner) Version() string { return "1.0" }

// Kind implements scanner.VersionedScanner.
func (*RepositoryScanner) Kind() string { return "repository" }

// Scan gets Red Hat repositories based on CPE information
func (rs *RepositoryScanner) Scan(ctx context.Context, l *claircore.Layer) (repositories []*claircore.Repository, err error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := zerolog.Ctx(ctx).With().
		Str("component", "rhel/RepositoryScanner.Scan").
		Str("version", rs.Version()).
		Str("layer", l.Hash.String()).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")

	cpes, err := getCpesUsingEmbeddedContentSets(l)
	if err != nil {
		return []*claircore.Repository{}, err
	}
	if len(cpes) == 0 {
		// Embedded content-sets are available only for new images
		// For old images let's use fallback option and query Red Hat Container API
		cpes, err = rs.getCpesUsingContainerApi(l)

	}
	for _, cpe := range cpes {
		repository := &claircore.Repository{
			Name: cpe,
			Key:  RedHatCPERepositoryKey,
		}
		repositories = append(repositories, repository)
	}

	return repositories, nil
}

func getCpesUsingEmbeddedContentSets(l *claircore.Layer) ([]string, error) {
	// TODO: get CPEs using embedded content-set files
	// content-set file will be stored most likely in /root/buildinfo/
	// content-sets need to be translated using mapping file provided
	// by Red Hat's PST team
	return []string{}, nil
}

func (rs *RepositoryScanner) getCpesUsingContainerApi(l *claircore.Layer) ([]string, error) {
	dockerfilePath, dockerFileContent, err := findDockerfile(l)
	if err != nil {
		if err == claircore.ErrNotFound {
			return []string{}, nil
		}
		return nil, err
	}
	if dockerFileContent == nil {
		return []string{}, nil
	}

	nvr, arch := extractBuildNVR(dockerfilePath, dockerFileContent)
	if nvr == "" || arch == "" {
		return []string{}, nil
	}
	cpes, err := rs.CpeFetcher.GetCPEs(nvr, arch)
	if err != nil {
		return []string{}, nil
	}
	return cpes, nil
}

// findDockerfile finds dockerfile in layer tarball and returns its name and content
func findDockerfile(l *claircore.Layer) (string, *bytes.Buffer, error) {
	// Dockerfile which was used to build given image/layer is stored by OSBS in /root/buildinfo/
	// Name of dockerfiles is in following format "Dockerfile-NAME-VERSION-RELEASE"
	// Name, version and release are labels defined in the dockerfile
	files, err := l.FilesByRegexp("/root/buildinfo/Dockerfile-.*")
	if err != nil {
		return "", nil, err
	}
	if len(files) == 0 {
		// no dockerfile has been found
		return "", nil, nil
	}
	// there should be always just one Dockerfile - return the first from a map
	for filename, fileContent := range files {
		return filename, fileContent, nil
	}
	return "", nil, nil
}

// extractBuildNVR - extract build NVR (name-version-release) from Dockerfile
// stored in filesystem
// The redhat.com.component LABEL is extracted from dockerfile and it is used as name
// Version and release is extracted from Dockerfile name
// Arch is extracted from 'architecture' LABEL
func extractBuildNVR(dockerfilePath string, dockerfileContent *bytes.Buffer) (nvr, arch string) {
	df, _ := dockerfile.ParseReader(dockerfileContent)
	var name string
	envVariable := interpolate.NewMapEnv(buildVarMap(df))
	for _, cmd := range df {
		if cmd.Cmd == "label" {
			for i, value := range cmd.Value {
				switch strings.Trim(value, "\"") {
				case "com.redhat.component":
					name = strings.Trim(cmd.Value[i+1], "\"")
					interpolatedName, err := interpolateName(name, envVariable)
					if err != nil {
						log.Debug().Msg("Can't interpolate name from Dockerfile" + name)
					} else {
						name = interpolatedName
					}
				case "architecture":
					arch = strings.Trim(cmd.Value[i+1], "\"")
				}

			}
		}
	}
	_, fileName := filepath.Split(dockerfilePath)
	version, release := parseVersionRelease(fileName)
	nvr = name + "-" + version + "-" + release
	return
}

func buildVarMap(commands []dockerfile.Command) map[string]string {
	output := make(map[string]string)
	for _, cmd := range commands {
		if cmd.Cmd == "env" || cmd.Cmd == "arg" {
			for i := 0; i < len(cmd.Value)-1; i = i + 2 {
				key := strings.Trim(cmd.Value[i], "\"")
				output[key] = strings.Trim(cmd.Value[i+1], "\"")
			}
		}
	}
	return output
}

func interpolateName(name string, envVariable interpolate.Env) (interpolatedName string, err error) {
	interpolatedName, err = interpolate.Interpolate(envVariable, name)
	if err != nil {
		return interpolatedName, err
	}
	if name == interpolatedName {
		// no interpolation has been done
		return interpolatedName, nil
	}
	// there is still some variable in name
	return interpolateName(interpolatedName, envVariable)
}

// parseVersionRelease - parse release and version from NVR
func parseVersionRelease(nvr string) (version, release string) {
	releaseIndex := strings.LastIndex(nvr, "-")
	release = nvr[releaseIndex+1:]

	versionIndex := strings.LastIndex(nvr[:releaseIndex], "-")
	version = nvr[versionIndex+1 : releaseIndex]
	return
}
