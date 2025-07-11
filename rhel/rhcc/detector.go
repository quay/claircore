package rhcc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"time"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
	"github.com/quay/claircore/pkg/rhctag"
	"github.com/quay/claircore/toolkit/types/cpe"
)

var (
	_ indexer.PackageScanner    = (*detector)(nil)
	_ indexer.RepositoryScanner = (*repoDetector)(nil)

	labelsFilepath = "root/buildinfo/labels.json"
)

type detector struct{}

// Name implements [indexer.VersionedScanner].
func (s *detector) Name() string { return "rhel_package_container_detector" }

// Version implements [indexer.VersionedScanner].
func (s *detector) Version() string { return "1" }

// Kind implements [indexer.VersionedScanner].
func (s *detector) Kind() string { return "package" }

// Scan performs a package scan on the given layer and returns all
// the RHEL container identifying metadata by using the labels.json file.

// Scan implements [indexer.PackageScanner].
func (s *detector) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Package, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/detector.Scan")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to open layer: %w", err)
	}

	labels, err := findJSONLabels(ctx, sys)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errNotFound):
		return nil, nil
	default:
		return nil, err
	}

	// Check if required fields are present
	if labels.Name == "" || labels.Architecture == "" || labels.Created.IsZero() {
		zlog.Warn(ctx).Msg("required labels not found in labels.json")
		return nil, nil
	}

	vr := strconv.FormatInt(labels.Created.Unix(), 10)
	rhctagVersion, err := rhctag.Parse(vr)
	if err != nil {
		// A unix timestamp should always parse, so this is unexpected.
		return nil, nil
	}

	normVer := rhctagVersion.Version(true)
	src := claircore.Package{
		Kind:              claircore.SOURCE,
		Name:              labels.Name,
		Version:           vr,
		NormalizedVersion: normVer,
		PackageDB:         labelsFilepath,
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
		PackageDB:         labelsFilepath,
		Arch:              labels.Architecture,
		RepositoryHint:    `rhcc`,
	})
	return pkgs, nil
}

// findJSONLabels reads and parses root/buildinfo/labels.json
// Schema: see testdata/labels.schema.json
func findJSONLabels(ctx context.Context, sys fs.FS) (*labels, error) {
	l, err := fs.ReadFile(sys, labelsFilepath)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		return nil, errNotFound
	default:
		return nil, err
	}
	var labels labels
	err = json.Unmarshal(l, &labels)
	if err != nil {
		return nil, err
	}
	return &labels, nil
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

// Scan performs a repository scan on the given layer and returns all
// the RHEL container identifying metadata by using the labels.json file.
//
// Scan implements [indexer.RepositoryScanner].
func (s *repoDetector) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Repository, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/repoDetector.Scan")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to open layer: %w", err)
	}
	labels, err := findJSONLabels(ctx, sys)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errNotFound):
		return nil, nil
	default:
		return nil, err
	}
	if labels.CPE != "" {
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
	return []*claircore.Repository{}, nil
}
