package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/klauspost/compress/zstd"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/ref"

	"github.com/quay/claircore/toolkit/fixtures"
)

var compressedTypes = []string{
	fixtures.MediaTypeZstdVEX,
	fixtures.MediaTypeZstdManifest,
}

// ErrNotAFixture is returned when an image lacks the required referrer artifacts
// (vulnerability manifest and/or CSAF documents) to be treated as a test fixture.
// This is acceptable as existing repos can contain non-fixture images.
var ErrNotAFixture = errors.New("image is not a test fixture")

// LoaderOption configures the fixture loader.
type LoaderOption func(*loaderConfig)

type loaderConfig struct {
	rcOpts  []regclient.Opt
	fixture *Fixture
}

// WithFixture provides a pre-loaded fixture, bypassing registry fetching.
// This is primarily useful for testing.
//
// Note: When using WithFixture with [Run], only a single reference should be
// provided. The same fixture is returned for all references, ignoring which
// reference was requested. For testing multiple fixtures, use real registry
// fixtures with OCI referrers or call [Run] multiple times.
func WithFixture(f *Fixture) LoaderOption {
	return func(c *loaderConfig) {
		c.fixture = f
	}
}

// WithDockerCreds uses credentials from local machine.
func WithDockerCreds() LoaderOption {
	return func(c *loaderConfig) {
		c.rcOpts = append(c.rcOpts, regclient.WithDockerCreds())
	}
}

// WithDockerCerts uses TLS certificates from local cert directories.
func WithDockerCerts() LoaderOption {
	return func(c *loaderConfig) {
		c.rcOpts = append(c.rcOpts, regclient.WithDockerCerts())
	}
}

// LoadFixture fetches a fixture from an OCI registry using the Referrers API.
//
// The reference can be:
//   - A registry reference: "registry.io/repo:tag" or "registry.io/repo@sha256:..."
//   - An OCI Layout directory: "ocidir:///path/to/layout"
//
// If WithFixture is provided, that fixture is returned directly without fetching.
func LoadFixture(ctx context.Context, reference string, opts ...LoaderOption) (*Fixture, error) {
	cfg := &loaderConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// If a fixture was provided directly, return it
	if cfg.fixture != nil {
		return cfg.fixture, nil
	}

	// Default to docker creds/certs if none specified
	if len(cfg.rcOpts) == 0 {
		cfg.rcOpts = append(cfg.rcOpts,
			regclient.WithDockerCreds(),
			regclient.WithDockerCerts(),
		)
	}

	rc := regclient.New(cfg.rcOpts...)

	r, err := ref.New(reference)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", reference, err)
	}
	defer rc.Close(ctx, r)

	// Resolve the manifest to get the digest
	m, err := rc.ManifestHead(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("resolve manifest: %w", err)
	}

	fix := &Fixture{
		Reference: reference,
		Manifest:  m.GetDescriptor().Digest.String(),
	}

	// Query referrers for the manifest
	rl, err := rc.ReferrerList(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("list referrers: %w", err)
	}

	// Process each referrer based on artifact type
	for _, desc := range rl.Descriptors {
		artifactType := desc.ArtifactType
		if artifactType == "" {
			artifactType = desc.MediaType
		}

		if err := processReferrer(ctx, rc, r, desc, artifactType, fix); err != nil {
			return nil, err
		}
	}

	if len(fix.Expected) == 0 {
		return nil, fmt.Errorf("%w: %q missing vulnerability manifest", ErrNotAFixture, reference)
	}
	if len(fix.VEXDocuments) == 0 {
		return nil, fmt.Errorf("%w: %q missing CSAF documents", ErrNotAFixture, reference)
	}

	return fix, nil
}

func processReferrer(ctx context.Context, rc *regclient.RegClient, r ref.Ref, desc descriptor.Descriptor, artifactType string, fix *Fixture) error {
	// The referrer descriptor points to an artifact manifest, not the blob directly.
	// We need to fetch the manifest and extract the blob from its layers.
	artifactRef := r.SetDigest(desc.Digest.String())
	m, err := rc.ManifestGet(ctx, artifactRef)
	if err != nil {
		return fmt.Errorf("fetch artifact manifest: %w", err)
	}

	// Get layers from the manifest - the content is in the first layer
	layers, err := m.GetLayers()
	if err != nil {
		return fmt.Errorf("get artifact layers: %w", err)
	}
	if len(layers) == 0 {
		return fmt.Errorf("artifact has no layers")
	}

	// Fetch the blob from the first layer
	layerDesc := layers[0]

	switch artifactType {
	case fixtures.MediaTypeVEX, fixtures.MediaTypeZstdVEX:
		compressed := slices.Contains(compressedTypes, artifactType) || slices.Contains(compressedTypes, layerDesc.MediaType)
		data, err := fetchBlob(ctx, rc, r, layerDesc, compressed)
		if err != nil {
			return fmt.Errorf("fetch VEX blob: %w", err)
		}
		fix.VEXDocuments = append(fix.VEXDocuments, data)

	case fixtures.MediaTypeManifest, fixtures.MediaTypeZstdManifest:
		compressed := slices.Contains(compressedTypes, artifactType) || slices.Contains(compressedTypes, layerDesc.MediaType)
		data, err := fetchBlob(ctx, rc, r, layerDesc, compressed)
		if err != nil {
			return fmt.Errorf("fetch vulnerability manifest blob: %w", err)
		}
		seq, err := fixtures.ParseManifest(ctx, artifactType, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("parse vulnerability manifest: %w", err)
		}
		for rec, err := range seq {
			if err != nil {
				return fmt.Errorf("parse vulnerability manifest: %w", err)
			}
			fix.Expected = append(fix.Expected, rec)
		}

	}

	return nil
}

// FetchBlob retrieves a blob from the registry, decompressing if needed.
func fetchBlob(ctx context.Context, rc *regclient.RegClient, r ref.Ref, desc descriptor.Descriptor, compressed bool) ([]byte, error) {
	blob, err := rc.BlobGet(ctx, r, desc)
	if err != nil {
		return nil, err
	}
	defer blob.Close()

	if compressed {
		dec, err := zstd.NewReader(blob)
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		return io.ReadAll(dec)
	}
	return io.ReadAll(blob)
}

