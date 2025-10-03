package rhcc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/toolkit/types/cpe"
)

var (
	_ indexer.PackageScanner    = (*detector)(nil)
	_ indexer.RepositoryScanner = (*repoDetector)(nil)

	// labelsFilepath is the path to the labels.json file in the layer.
	labelsFilepath = "root/buildinfo/labels.json"
	// altLabelsFilepath is the path to the labels.json file used by RHCOS and other images.
	altLabelsFilepath = "usr/share/buildinfo/labels.json"
)

type detector struct{}

// Name implements [indexer.VersionedScanner].
func (s *detector) Name() string { return "rhel_package_container_detector" }

// Version implements [indexer.VersionedScanner].
func (s *detector) Version() string { return "1" }

// Kind implements [indexer.VersionedScanner].
func (s *detector) Kind() string { return "package" }

// Scan implements [indexer.PackageScanner].
//
// It performs a package scan on the given layer and returns all the RHEL
// container identifying metadata by using the labels.json file.
func (s *detector) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to open layer: %w", err)
	}

	labels, labelsPath, err := findLabelsJSON(sys)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Check if required fields are present
	if labels.Name == "" || labels.Architecture == "" || labels.Created.IsZero() {
		slog.WarnContext(ctx, "required labels not found in labels.json")
		return nil, nil
	}

	vr := strconv.FormatInt(labels.Created.Unix(), 10)
	rhctagVersion, err := rhctag.Parse(vr)
	if err != nil {
		// A unix timestamp should always parse, so this is unexpected.
		slog.WarnContext(ctx, "failed to parse rhctag version", "reason", err, "version", vr)
		return nil, nil
	}

	normVer := rhctagVersion.Version(true)
	src := claircore.Package{
		Kind:              claircore.SOURCE,
		Name:              labels.Name,
		Version:           vr,
		NormalizedVersion: normVer,
		PackageDB:         labelsPath,
		Arch:              labels.Architecture,
		RepositoryHint:    `rhcc`,
	}
	pkgs := []*claircore.Package{&src}

	pkgs = append(pkgs, &claircore.Package{
		Kind:              claircore.BINARY,
		Name:              labels.Name,
		Version:           vr,
		NormalizedVersion: normVer,
		Source:            &src,
		PackageDB:         labelsPath,
		Arch:              labels.Architecture,
		RepositoryHint:    `rhcc`,
	})
	return pkgs, nil
}

// findLabelsJSON tries known locations and returns the first parsed labels
// along with the path that succeeded.
// See testdata/labels.schema.json
func findLabelsJSON(sys fs.FS) (*labels, string, error) {
	for _, p := range []string{labelsFilepath, altLabelsFilepath} {
		l, err := fs.ReadFile(sys, p)
		switch {
		case errors.Is(err, nil):
			var lb labels
			if err := json.Unmarshal(l, &lb); err != nil {
				return nil, "", err
			}
			return &lb, p, nil
		case errors.Is(err, fs.ErrNotExist):
			continue
		default:
			return nil, "", err
		}
	}
	return nil, "", errNotFound
}

type labels struct {
	Created      time.Time `json:"org.opencontainers.image.created"`
	Architecture string    `json:"architecture"`
	Name         string    `json:"name"`
	CPE          string    `json:"cpe"`
}

type repoDetector struct{}

var _ indexer.RepositoryScanner = (*repoDetector)(nil)

// Name implements [indexer.VersionedScanner].
func (s *repoDetector) Name() string { return "rhel_repo_container_detector" }

// Version implements [indexer.VersionedScanner].
func (s *repoDetector) Version() string { return "1" }

// Kind implements [indexer.VersionedScanner].
func (s *repoDetector) Kind() string { return "repository" }

// Scan implements [indexer.RepositoryScanner].
//
// It performs a repository scan on the given layer and returns all the RHEL
// container identifying metadata by using the labels.json file.
func (s *repoDetector) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Repository, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to open layer: %w", err)
	}
	labels, _, err := findLabelsJSON(sys)
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if labels.CPE == "" {
		return []*claircore.Repository{}, nil
	}

	wfn, err := cpe.Unbind(labels.CPE)
	if err != nil {
		return nil, err
	}
	return []*claircore.Repository{
		{
			CPE:  wfn,
			Name: wfn.String(),
			Key:  RepositoryKey,
		},
	}, nil
}
