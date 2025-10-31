// Package rhel implements the machinery for processing layers and security data
// from the Red Hat ecosystem.
//
// See the various exported types for details on the heuristics employed.
//
// In addition, containers themselves are recognized via the
// [github.com/quay/claircore/rhel/rhcc] package.
package rhel // import "github.com/quay/claircore/rhel"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
)

// GetContentManifest reads and parses the content manifest file from the layer.
// Content manifest files are stored in /root/buildinfo/content_manifests/ or
// /usr/share/buildinfo/ (for RHCOS) and contain information about how the container
// should be processed.
func getContentManifest(ctx context.Context, sys fs.FS) (*contentManifest, error) {
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
	slog.DebugContext(ctx, "found content manifest file", "manifest-path", p)
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
		slog.WarnContext(ctx, "could not unmarshal content_manifests file",
			"manifest-path", p,
			"reason", err)
		return nil, nil
	default:
		return nil, err
	}

	return &m, nil
}

// ContentManifest represents data provided by OSBS (OpenShift Build Service and Konflux).
type contentManifest struct {
	ContentSets []string         `json:"content_sets"`
	Metadata    manifestMetadata `json:"metadata"`
	// FromDNFHint indicates whether DNF metadata should be looked up during indexing.
	// If true or if the content manifest is absent, DNF methods are preferred.
	// If false, legacy content-sets are used.
	FromDNFHint bool `json:"from_dnf_hint"`
}

// ManifestMetadata struct holds additional metadata about the build.
type manifestMetadata struct {
	ImageLayerIndex int `json:"image_layer_index"`
}
