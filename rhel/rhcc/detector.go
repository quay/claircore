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
	_ indexer.PackageScanner = (*detector)(nil)
	// createdLabelLayout is time.RFC3339 without timezone.
	createdLabelLayout = "2006-01-02T15:04:05"
	labelsFilepath     = "root/buildinfo/labels.json"
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
	const (
		nameLabel    = `name`
		archLabel    = `architecture`
		createdLabel = "org.opencontainers.image.created"
	)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sys, err := l.FS()
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to open layer: %w", err)
	}

	var vr string
	labels, err := findJSONLabels(ctx, sys)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, errNotFound):
		return nil, nil
	default:
		return nil, err
	}

	var created, arch, name string
	for _, chk := range []struct {
		Found *string
		Want  string
	}{
		{&created, createdLabel},
		{&arch, archLabel},
		{&name, nameLabel},
	} {
		var ok bool
		(*chk.Found), ok = labels[chk.Want]
		if !ok {
			zlog.Info(ctx).Str("label", chk.Want).Msg("expected label not found in labels.json")
			return nil, nil
		}
	}
	dt, err := time.Parse(createdLabelLayout, created)
	if err != nil {
		return nil, fmt.Errorf("rhcc: unable to parse org.opencontainers.image.created label: %w", err)
	}
	vr = strconv.FormatInt(dt.Unix(), 10)
	rhctagVersion, err := rhctag.Parse(vr)
	if err != nil {
		// A unix timestamp should always parse, so this is unexpected.
		return nil, nil
	}

	normVer := rhctagVersion.Version(true)
	src := claircore.Package{
		Kind:              claircore.SOURCE,
		Name:              name,
		Version:           vr,
		NormalizedVersion: normVer,
		PackageDB:         labelsFilepath,
		Arch:              arch,
		RepositoryHint:    `rhcc`,
	}
	pkgs := []*claircore.Package{&src}

	pkgs = append(pkgs, &claircore.Package{
		Kind:              claircore.BINARY,
		Name:              name,
		Version:           vr,
		NormalizedVersion: normVer,
		Source:            &src,
		PackageDB:         labelsFilepath,
		Arch:              arch,
		RepositoryHint:    `rhcc`,
	})
	return pkgs, nil
}

func findJSONLabels(ctx context.Context, sys fs.FS) (map[string]string, error) {
	labels := make(map[string]string)
	l, err := fs.ReadFile(sys, labelsFilepath)
	switch {
	case errors.Is(err, nil):
	case errors.Is(err, fs.ErrNotExist):
		return nil, errNotFound
	default:
		return nil, err
	}
	err = json.Unmarshal(l, &labels)
	if err != nil {
		return nil, err
	}
	return labels, nil
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
	if c, ok := labels["cpe"]; ok {
		wfn, err := cpe.Unbind(c)
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
