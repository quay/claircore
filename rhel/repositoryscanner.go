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
	"slices"
	"strings"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/dnf"
	"github.com/quay/claircore/internal/zreader"
	"github.com/quay/claircore/rhel/dockerfile"
	"github.com/quay/claircore/rhel/internal/common"
	"github.com/quay/claircore/rhel/internal/containerapi"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// RepositoryScanner implements repository detection logic for RHEL.
//
// The RHEL detection logic needs outside information because the Red Hat build
// system does not (and did not, in the past) store the relevant information in
// the layer itself. In addition, dnf and yum do not persist provenance
// information outside of a cache and rpm considers such information outside its
// baliwick.
//
// In the case of the RHEL ecosystem, "repository" is a bit of a misnomer, as
// advisories are tracked on the Product level, and so Clair's "repository" data
// is used instead to indicate a Product. This mismatch can lead to apparent
// duplication in reporting. For example, if an advisory is marked as affecting
// "cpe:/a:redhat:enterprise_linux:8" and
// "cpe:/a:redhat:enterprise_linux:8::appstream", this results in two advisories
// being recorded. (CPEs do not namespace the way this example may imply; that
// is to say, the latter is not "contained in" or a "member of" the former.) If
// a layer reports that it is both the "cpe:/a:redhat:enterprise_linux:8" and
// "cpe:/a:redhat:enterprise_linux:8::appstream" layer, then both advisories
// match.
type RepositoryScanner struct {
	// These members are created after the Configure call.
	upd        *common.Updater
	apiFetcher *containerapi.ContainerAPI
	client     *http.Client

	cfg RepositoryScannerConfig
}

var (
	_ indexer.RepositoryScanner = (*RepositoryScanner)(nil)
	_ indexer.RPCScanner        = (*RepositoryScanner)(nil)
	_ indexer.VersionedScanner  = (*RepositoryScanner)(nil)
)

// RepositoryScannerConfig is the configuration expected for a
// [RepositoryScanner].
//
// Providing the "URL" and "File" members controls how the RepositoryScanner
// handles updating its mapping file:
//
//   - If the "URL" is provided or no configuration is provided, the mapping file
//     is fetched at construction time and then updated periodically.
//   - If only the "File" is provided, it will be consulted exclusively.
//   - If both the "URL" and "File" are provided, the file will be loaded
//     initially and then updated periodically from the URL.
type RepositoryScannerConfig struct {
	// API is the URL to talk to the Red Hat Container API.
	//
	// See [DefaultContainerAPI] and [containerapi.ContainerAPI].
	API string `json:"api" yaml:"api"`
	// Repo2CPEMappingURL can be used to fetch the repo mapping file.
	// Consulting the mapping file is preferred over the Container API.
	//
	// See [DefaultRepo2CPEMappingURL] and [repo2cpe].
	Repo2CPEMappingURL string `json:"repo2cpe_mapping_url" yaml:"repo2cpe_mapping_url"`
	// Repo2CPEMappingFile, if specified, is consulted instead of the [Repo2CPEMappingURL].
	//
	// This should be provided to avoid any network traffic.
	Repo2CPEMappingFile string `json:"repo2cpe_mapping_file" yaml:"repo2cpe_mapping_file"`
	// Timeout controls the timeout for any remote calls this package makes.
	//
	// The default is 10 seconds.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// DisableAPI disables the use of the API.
	DisableAPI bool `json:"disable_api" yaml:"disable_api"`
}

const (
	// RepositoryKey marks a repository as being based on a Red Hat CPE.
	repositoryKey = "rhel-cpe-repository"
	// DefaultContainerAPI is the default Red Hat Container API URL.
	//
	//doc:url indexer
	DefaultContainerAPI = "https://catalog.redhat.com/api/containers/"
	// DefaultRepo2CPEMappingURL is default URL with a mapping file provided by Red Hat.
	//
	//doc:url indexer
	DefaultRepo2CPEMappingURL = "https://security.access.redhat.com/data/metrics/repository-to-cpe.json"
)

// Name implements [indexer.VersionedScanner].
func (*RepositoryScanner) Name() string { return "rhel-repository-scanner" }

// Version implements [indexer.VersionedScanner].
func (*RepositoryScanner) Version() string { return "2" }

// Kind implements [indexer.VersionedScanner].
func (*RepositoryScanner) Kind() string { return "repository" }

// Configure implements [indexer.RPCScanner].
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
		r.cfg.API = DefaultContainerAPI
	}
	if r.cfg.Timeout == 0 {
		r.cfg.Timeout = 10 * time.Second
	}

	var mf *mappingFile
	switch {
	case r.cfg.Repo2CPEMappingURL == "" && r.cfg.Repo2CPEMappingFile == "":
		// defaults
		r.cfg.Repo2CPEMappingURL = DefaultRepo2CPEMappingURL
	case r.cfg.Repo2CPEMappingURL != "" && r.cfg.Repo2CPEMappingFile == "":
		// remote only
	case r.cfg.Repo2CPEMappingFile != "":
		// seed from file
		f, err := os.Open(r.cfg.Repo2CPEMappingFile)
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
	r.upd = common.NewUpdater(r.cfg.Repo2CPEMappingURL, mf)
	tctx, done := context.WithTimeout(ctx, r.cfg.Timeout)
	defer done()
	r.upd.Get(tctx, c)

	if r.cfg.DisableAPI {
		zlog.Debug(ctx).Msg("container API disabled")
	} else {
		// Additional setup
		root, err := url.Parse(r.cfg.API)
		if err != nil {
			return err
		}

		r.apiFetcher = &containerapi.ContainerAPI{
			Root:   root,
			Client: r.client,
		}
	}

	return nil
}

// Scan implements [indexer.RepositoryScanner].
func (r *RepositoryScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Repository, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/RepositoryScanner.Scan",
		"version", r.Version(),
		"layer", l.Hash.String())
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open layer: %w", err)
	}

	tctx, done := context.WithTimeout(ctx, r.cfg.Timeout)
	defer done()
	cmi, err := r.upd.Get(tctx, r.client)
	if err != nil && cmi == nil {
		return []*claircore.Repository{}, err
	}
	cm, ok := cmi.(*mappingFile)
	if !ok || cm == nil {
		return []*claircore.Repository{}, fmt.Errorf("rhel: unable to create a mappingFile object")
	}

	// First, look at DNF.
	repoids, err := dnf.FindRepoids(ctx, sys)
	switch {
	case err != nil: // continue to error check and return
	case len(repoids) == 0:
		// If DNF yielded nothing, check for content-sets data.
		repoids, err = repoidsFromContentSets(ctx, sys)
	default:
	}
	if err != nil {
		return []*claircore.Repository{}, err
	}

	pairs := func(yield func(string, string) bool) {
		var found bool
		for _, repoid := range repoids {
			cpes, ok := cm.GetOne(ctx, repoid)
			if !ok {
				continue
			}
			found = true
			for _, cpe := range cpes {
				if !yield(repoid, cpe) {
					return
				}
			}
		}
		if found {
			return
		}

		if r.apiFetcher != nil {
			// Embedded content-sets are unavailable in very old images.
			// For these, use fallback option and query Red Hat Container API.
			ctx, done := context.WithTimeout(ctx, r.cfg.Timeout)
			defer done()

			// !!! This ends up being a weird nonlocal return. !!!
			var cpes []string
			cpes, err = mapContainerAPI(ctx, sys, r.apiFetcher)
			if err != nil {
				zlog.Warn(ctx).
					Err(err).
					Msg("container API error")
				return
			}
			for _, cpe := range cpes {
				if !yield("", cpe) {
					return
				}
			}
		}
	}
	var repositories []*claircore.Repository
	for repoid, cpeID := range pairs {
		// TODO(hank) Remove these ContainerAPI hacks:
		// Start ContainerAPI hacks
		if err != nil {
			return []*claircore.Repository{}, err
		}
		if repoid == "" {
			repoid = cpeID
		}
		// End ContainerAPI hacks

		r := &claircore.Repository{
			Name: repoid,
			Key:  repositoryKey,
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
	slices.SortFunc(repositories, func(a, b *claircore.Repository) int {
		if ord := strings.Compare(a.Name, b.Name); ord != 0 {
			return ord
		}
		if ord := strings.Compare(a.CPE.BindFS(), b.CPE.BindFS()); ord != 0 {
			return ord
		}
		return 0
	})
	repositories = slices.CompactFunc(repositories, func(a, b *claircore.Repository) bool {
		return a.Name == b.Name && a.CPE.BindFS() == b.CPE.BindFS()
	})

	return repositories, nil
}

// RepoidsFromContentSets returns a slice of repoids, as discovered by examining
// information contained within the container.
func repoidsFromContentSets(ctx context.Context, sys fs.FS) ([]string, error) {
	// Get repoids using embedded content-set files. The files are stored in
	// /root/buildinfo/content_manifests/ and will need to be translated using
	// mapping file provided by Red Hat's PST team. For RHCOS, the files are
	// stored in /usr/share/buildinfo/.
	ms, err := fs.Glob(sys, `root/buildinfo/content_manifests/*.json`)
	if err != nil {
		panic("programmer error: " + err.Error())
	}
	ms2, err := fs.Glob(sys, `usr/share/buildinfo/*.json`)
	if err != nil {
		panic("programmer error: " + err.Error())
	}
	ms = append(ms, ms2...)
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
	var m contentManifest
	var syntaxErr *json.SyntaxError
	err = json.Unmarshal(b, &m)
	switch {
	case errors.Is(err, nil):
	case errors.As(err, &syntaxErr):
		zlog.Warn(ctx).
			Str("manifest-path", p).
			Err(err).
			Msg("could not unmarshal content_manifests file")
		return nil, nil
	default:
		return nil, err
	}
	// If the JSON file is malformed and has a 0-length list of content sets,
	// report nil so that the API can be consulted.
	if len(m.ContentSets) == 0 {
		return nil, nil
	}
	return m.ContentSets, nil
}

// MappingFile is a data struct for mapping file between repositories and CPEs
type mappingFile struct {
	Data map[string]repo `json:"data"`
}

// Repo structure holds information about CPEs for given repo
type repo struct {
	CPEs []string `json:"cpes"`
}

// GetOne takes a repoid and reports the CPEs and if the repoid was known
// beforehand.
func (m *mappingFile) GetOne(ctx context.Context, repoid string) (cpes []string, ok bool) {
	if repo, ok := m.Data[repoid]; ok {
		return repo.CPEs, true
	}
	zlog.Debug(ctx).
		Str("repository", repoid).
		Msg("repository not present in a mapping file")
	return nil, false
}

// ContentManifest structure is the data provided by OSBS.
type contentManifest struct {
	ContentSets []string         `json:"content_sets"`
	Metadata    manifestMetadata `json:"metadata"`
}

// ManifestMetadata struct holds additional metadata about the build.
type manifestMetadata struct {
	ImageLayerIndex int `json:"image_layer_index"`
}

// MapContainerAPI returns a slice of CPEs bound into strings, as discovered by
// pulling labels from the Dockerfile contained in the layer and submitted to the
// Container API.
func mapContainerAPI(ctx context.Context, sys fs.FS, api *containerapi.ContainerAPI) ([]string, error) {
	ms, err := fs.Glob(sys, "root/buildinfo/Dockerfile-*")
	if err != nil {
		panic("programmer error: " + err.Error())
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

	cpes, err := api.GetCPEs(ctx, nvr, arch)
	if err != nil {
		return nil, err
	}
	zlog.Debug(ctx).
		Str("nvr", nvr).
		Str("arch", arch).
		Strs("cpes", cpes).
		Msg("got CPEs from container API")
	return cpes, nil
}

// ExtractBuildNVR extracts the build's NVR and arch from the named Dockerfile and its contents.
//
// The `redhat.com.component` label is extracted from the contents and used as the "name."
// "Version" and "release" are extracted from the Dockerfile path.
// "Arch" is extracted from the `architecture` label.
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

// MissingLabel is an error that provides information on which label was missing
// and "Is" errBadDockerfile.
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

// ParseVersionRelease reports the version and release from an NVR string.
func parseVersionRelease(nvr string) (version, release string) {
	releaseIndex := strings.LastIndex(nvr, "-")
	release = nvr[releaseIndex+1:]

	versionIndex := strings.LastIndex(nvr[:releaseIndex], "-")
	version = nvr[versionIndex+1 : releaseIndex]
	return
}
