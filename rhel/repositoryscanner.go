package rhel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/trace"
	"slices"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/internal/dnf"
	"github.com/quay/claircore/internal/zreader"
	"github.com/quay/claircore/rhel/dockerfile"
	"github.com/quay/claircore/rhel/internal/common"
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
	upd    *common.Updater
	client *http.Client

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
	// Repo2CPEMappingURL can be used to fetch the repo mapping file.
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
	// DefaultRepo2CPEMappingURL is default URL with a mapping file provided by Red Hat.
	//
	//doc:url indexer
	DefaultRepo2CPEMappingURL = "https://security.access.redhat.com/data/metrics/repository-to-cpe.json"
)

// Name implements [indexer.VersionedScanner].
func (*RepositoryScanner) Name() string { return "rhel-repository-scanner" }

// Version implements [indexer.VersionedScanner].
func (*RepositoryScanner) Version() string { return "3" }

// Kind implements [indexer.VersionedScanner].
func (*RepositoryScanner) Kind() string { return "repository" }

// Configure implements [indexer.RPCScanner].
func (r *RepositoryScanner) Configure(ctx context.Context, f indexer.ConfigDeserializer, c *http.Client) error {
	r.client = c
	if err := f(&r.cfg); err != nil {
		return err
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

	return nil
}

// Scan implements [indexer.RepositoryScanner].
//
// The two important pieces of information are the "repoid" and CPE, which are
// stored in the [claircore.Repository]'s "Name" and "CPE" fields, respectively.
func (r *RepositoryScanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Repository, error) {
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	slog.DebugContext(ctx, "start")
	defer slog.DebugContext(ctx, "done")

	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to open layer: %w", err)
	}

	useDNFData := false
	man, err := getContentManifest(ctx, sys)
	if err != nil {
		return nil, fmt.Errorf("rhel: unable to get content manifest: %w", err)
	}
	useDNFData = man == nil || man.FromDNFHint

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

	var repoids []string
	if useDNFData {
		repoids, err = dnf.FindRepoids(ctx, sys)
	} else {
		repoids, err = repoidsFromContentSets(ctx, sys)
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
	}
	var repositories []*claircore.Repository
	for repoid, cpeID := range pairs {
		c, err := cpe.Unbind(cpeID)
		if err != nil {
			slog.WarnContext(ctx, "invalid CPE, please report a bug upstream",
				"reason", err,
				"cpeID", cpeID,
				"url", bugURL(cpeID, err))
			continue
		}

		uri := url.Values{
			"repoid": {repoid},
		}
		r := &claircore.Repository{
			Key:  repositoryKey,
			Name: c.BindFS(),
			CPE:  c,
			URI:  uri.Encode(),
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
		return a.Name == b.Name && a.CPE.BindFS() == b.CPE.BindFS() && a.URI == b.URI
	})

	return repositories, nil
}

// BugURL constructs a link directly to the Red Hat Jira instance.
func bugURL(id string, err error) *url.URL {
	const desc = "A Clair instance noticed an invalid CPE:{code}%s{code}\nThe reported error was:{code}%v{code}"
	v := url.Values{
		"pid":         {"12330022"}, // ID for the Red Hat Jira "SECDATA" project.
		"issuetype":   {"1"},
		"summary":     {"invalid CPE in Red Hat data"},
		"description": {fmt.Sprintf(desc, id, err)},
	}
	u := url.URL{
		Scheme:   "https",
		Host:     "issues.redhat.com",
		Path:     "/secure/CreateIssueDetails!init.jspa",
		RawQuery: v.Encode(),
	}
	return &u
}

// RepoidsFromContentSets returns a slice of repoids, as discovered by examining
// information contained within the container. Found repoids will need to be translated
// using a mapping file provided by Red Hat's PST team.
func repoidsFromContentSets(ctx context.Context, sys fs.FS) ([]string, error) {
	cm, err := getContentManifest(ctx, sys)
	if err != nil {
		return nil, err
	}
	if cm == nil {
		return nil, nil
	}
	return cm.ContentSets, nil
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
	slog.DebugContext(ctx, "repository not present in a mapping file", "repository", repoid)
	return nil, false
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
