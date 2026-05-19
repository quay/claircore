package whiteout

import (
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/quay/claircore"
	"github.com/quay/claircore/indexer"
)

var _ indexer.Resolver = (*Resolver)(nil)

type Resolver struct{}

func (r *Resolver) Resolve(ctx context.Context, ir *claircore.IndexReport, layers []*claircore.Layer) *claircore.IndexReport {
	// Here we need to check if any of the packages
	// found are moot due to whiteouts.
	ls := newLayerSorter(layers)

	whiteouts := make(map[string][]string)
	for layer, files := range ir.Files {
		for path, kind := range files {
			if kind == claircore.FileKindWhiteout {
				whiteouts[layer] = append(whiteouts[layer], path)
			}
		}
	}

	finalPackages := map[string]*claircore.Package{}
	finalEnvironments := map[string][]*claircore.Environment{}
	for pkgID, pkg := range ir.Packages {
		packageDeleted := false
		// Check all layers where the package appeared for the newest one
		packageLayer := ir.Environments[pkgID][0].IntroducedIn.String()
		for i := 1; i < len(ir.Environments[pkgID]); i++ {
			if ls.isChildOf(ir.Environments[pkgID][i].IntroducedIn.String(), packageLayer) {
				packageLayer = ir.Environments[pkgID][i].IntroducedIn.String()
			}
		}
		// Check if it's a whiteout file, if it applies to the package's
		// filepath and if the layer the whiteout file came from came after.
		// The spec states: "Whiteout files MUST only apply to resources in
		// lower/parent layers" hence why we don't check if they're in the same
		// layer.
		for layer, paths := range whiteouts {
			if ls.isChildOf(layer, packageLayer) && slices.ContainsFunc(paths, func(p string) bool {
				return fileIsDeleted(pkg.Filepath, p)
			}) {
				packageDeleted = true
				break
			}
		}
		if packageDeleted {
			slog.DebugContext(ctx, "package determined to be deleted",
				"package name", pkg.Name,
				"package file", pkg.Filepath)
		} else {
			finalPackages[pkgID] = pkg
			finalEnvironments[pkgID] = ir.Environments[pkgID]
		}
	}
	ir.Packages = finalPackages
	ir.Environments = finalEnvironments
	return ir
}

// FileIsDeleted returns whether or not the filepath(fp) has been deleted
// by the corresponding whiteoutPath. It follows the OCI spec for whiteouts:
// https://github.com/opencontainers/image-spec/blob/main/layer.md#whiteouts
func fileIsDeleted(fp, whiteoutPath string) bool {
	var checkFile string
	fpParts := strings.Split(fp, "/")
	switch {
	case filepath.Base(whiteoutPath) == ".wh..wh..opq":
		// Special opaque case, "indicating that all siblings are hidden in the lower layer"
		checkFile = filepath.Dir(whiteoutPath)
		if checkFile == fp {
			// Account for the parent dir of the whiteout file
			return false
		}
	case strings.HasPrefix(filepath.Base(whiteoutPath), ".wh."):
		origFileName := filepath.Base(whiteoutPath)[4:]
		checkFile = filepath.Join(filepath.Dir(whiteoutPath), origFileName)
	default:
		return false
	}
	checkFileParts := strings.Split(checkFile, "/")
	if len(checkFileParts) > len(fpParts) {
		return false
	}
	for i, p := range checkFileParts {
		if p != fpParts[i] {
			return false
		}
	}
	return true
}

type layerSorter map[string]int

func newLayerSorter(layers []*claircore.Layer) layerSorter {
	ls := make(map[string]int, len(layers))
	for i, l := range layers {
		ls[l.Hash.String()] = i
	}
	return ls
}

// IsChildOf decides if whiteoutLayer comes after packageLayer in the layer
// hierarchy, i.e. is whiteoutLayer a child of packageLayer?
func (ls layerSorter) isChildOf(whiteoutLayer, packageLayer string) bool {
	return ls[whiteoutLayer] > ls[packageLayer]
}
