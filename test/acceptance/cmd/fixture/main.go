// Command fixture manages acceptance test fixtures in OCI registries.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/mediatype"
	v1 "github.com/regclient/regclient/types/oci/v1"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"

	"github.com/quay/claircore/toolkit/fixtures"
)

const defaultRepo = "quay.io/projectquay/clair-fixtures"

// TODO (crozzy): Add this somewhere common for all CLIs to use.
type logHandler struct{}

func (h *logHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *logHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(a.Value.String())
		return true
	})
	sb.WriteString("\n")
	fmt.Fprint(os.Stderr, sb.String())
	return nil
}

func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *logHandler) WithGroup(name string) slog.Handler       { return h }

// StringSlice implements flag.Value for repeated string flags.
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	slog.SetDefault(slog.New(&logHandler{}))

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var err error
	switch os.Args[1] {
	case "create":
		err = runCreate(ctx, os.Args[2:])
	case "list":
		err = runList(ctx, os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		slog.Error("unknown command", "cmd", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: go run ./test/acceptance/cmd/fixture <command> [options]

Commands:
  create    Create a test fixture from a source image
  list      List referrers attached to an image

Create options:
  -image <ref>       Source image reference (must include @sha256:... digest)
  -tag <name>        Tag name for the fixture image (e.g., golang, python-311)
  -vex <file>        Path to VEX document (repeatable for multiple files)
  -manifest <file>   Path to expected results (CSV format)
  -repo <repo>       Target repository (default: quay.io/projectquay/clair-fixtures)
  -platform <p>      Platform to copy (default: linux/amd64, use "all" to copy all)

List options:
  -image <ref>       Image reference to inspect

Examples:
  go run ./test/acceptance/cmd/fixture create -image registry.io/foo@sha256:abc... -tag mytest -vex vex1.json -vex vex2.json -manifest expected.csv
  go run ./test/acceptance/cmd/fixture list -image quay.io/projectquay/clair-fixtures:mytest
`)
}

func runCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	image := fs.String("image", "", "source image reference (with digest)")
	tag := fs.String("tag", "", "fixture tag name")
	var vexFiles stringSlice
	fs.Var(&vexFiles, "vex", "VEX document path (repeatable)")
	manifestFile := fs.String("manifest", "", "expected results CSV path")
	repo := fs.String("repo", defaultRepo, "target repository")
	plat := fs.String("platform", "linux/amd64", "platform to copy from manifest list")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *image == "" {
		return fmt.Errorf("-image is required")
	}
	if *tag == "" {
		return fmt.Errorf("-tag is required")
	}
	if len(vexFiles) == 0 {
		return fmt.Errorf("-vex is required (at least one)")
	}
	if *manifestFile == "" {
		return fmt.Errorf("-manifest is required")
	}
	if !strings.Contains(*image, "@sha256:") {
		return fmt.Errorf("image must include digest (@sha256:...)")
	}

	var vexDataSlice [][]byte
	for _, vf := range vexFiles {
		data, err := os.ReadFile(vf)
		if err != nil {
			return fmt.Errorf("error reading VEX file %q: %w", vf, err)
		}
		vexDataSlice = append(vexDataSlice, data)
	}
	manifestData, err := os.ReadFile(*manifestFile)
	if err != nil {
		return fmt.Errorf("error reading manifest file: %w", err)
	}

	srcRef, err := ref.New(*image)
	if err != nil {
		return fmt.Errorf("error parsing source image: %w", err)
	}
	target := fmt.Sprintf("%s:%s", *repo, *tag)
	dstRef, err := ref.New(target)
	if err != nil {
		return fmt.Errorf("error parsing target: %w", err)
	}

	rc := regclient.New(
		regclient.WithDockerCreds(),
		regclient.WithDockerCerts(),
	)
	defer rc.Close(ctx, srcRef)
	defer rc.Close(ctx, dstRef)

	slog.Info("removing existing fixture")
	if err := deleteFixture(ctx, rc, dstRef); err != nil {
		slog.Warn("cleanup failed", "error", err)
	}

	// If platform specified, resolve to the platform-specific manifest digest
	if *plat != "all" {
		p, err := platform.Parse(*plat)
		if err != nil {
			return fmt.Errorf("parse platform: %w", err)
		}
		m, err := rc.ManifestGet(ctx, srcRef, regclient.WithManifestPlatform(p))
		if err != nil {
			return fmt.Errorf("get platform manifest: %w", err)
		}
		srcRef = srcRef.SetDigest(m.GetDescriptor().Digest.String())
	}

	slog.Info("copying image", "src", srcRef.CommonName(), "dst", target)
	if err := rc.ImageCopy(ctx, srcRef, dstRef); err != nil {
		return fmt.Errorf("copy image: %w", err)
	}

	// TODO: Add claircore.fixture=true label to the image. This would allow
	// listing all fixtures in a repository via registry API label filtering.
	// Blocked on figuring out why regclient/mod.Apply fails after ImageCopy.

	m, err := rc.ManifestHead(ctx, dstRef, regclient.WithManifestRequireDigest())
	if err != nil {
		return fmt.Errorf("resolve target manifest: %w", err)
	}
	subjectDesc := m.GetDescriptor()

	// Push the empty config blob once (used by both artifact manifests)
	confDesc := descriptor.Descriptor{
		MediaType: mediatype.OCI1Empty,
		Digest:    descriptor.EmptyDigest,
		Size:      int64(len(descriptor.EmptyData)),
	}
	if _, err := rc.BlobPut(ctx, dstRef, confDesc, bytes.NewReader(descriptor.EmptyData)); err != nil {
		return fmt.Errorf("push empty config: %w", err)
	}

	slog.Info("attaching VEX documents", "count", len(vexDataSlice), "subject", subjectDesc.Digest.String())
	for i, vexData := range vexDataSlice {
		if err := attachArtifact(ctx, rc, dstRef, subjectDesc, confDesc, fixtures.MediaTypeVEX, vexData); err != nil {
			return fmt.Errorf("attach VEX %d: %w", i+1, err)
		}
	}

	slog.Info("attaching expected results manifest")
	if err := attachArtifact(ctx, rc, dstRef, subjectDesc, confDesc, fixtures.MediaTypeManifest, manifestData); err != nil {
		return fmt.Errorf("attach manifest: %w", err)
	}

	slog.Info("fixture created", "target", target)
	return nil
}

func attachArtifact(ctx context.Context, rc *regclient.RegClient, r ref.Ref, subject, conf descriptor.Descriptor, artifactType string, data []byte) error {
	d := digest.Canonical.FromBytes(data)
	desc := descriptor.Descriptor{
		MediaType: artifactType,
		Digest:    d,
		Size:      int64(len(data)),
	}

	if _, err := rc.BlobPut(ctx, r, desc, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("push blob: %w", err)
	}

	mm, err := manifest.New(manifest.WithOrig(v1.Manifest{
		Versioned:    v1.ManifestSchemaVersion,
		MediaType:    mediatype.OCI1Manifest,
		ArtifactType: artifactType,
		Config:       conf,
		Layers:       []descriptor.Descriptor{desc},
		Subject: &descriptor.Descriptor{
			MediaType: subject.MediaType,
			Digest:    subject.Digest,
			Size:      subject.Size,
		},
	}))
	if err != nil {
		return fmt.Errorf("create manifest: %w", err)
	}

	// Push referrer manifest by digest, not to the tag (which would overwrite the image!)
	referrerRef := r.SetDigest(mm.GetDescriptor().Digest.String())
	if err := rc.ManifestPut(ctx, referrerRef, mm); err != nil {
		return fmt.Errorf("push manifest: %w", err)
	}

	return nil
}

func deleteFixture(ctx context.Context, rc *regclient.RegClient, r ref.Ref) error {
	// Check if the tag exists
	m, err := rc.ManifestHead(ctx, r)
	if err != nil {
		return nil // Tag doesn't exist, nothing to clean up
	}

	// List and delete referrers
	rl, err := rc.ReferrerList(ctx, r)
	if err == nil && len(rl.Descriptors) > 0 {
		for _, desc := range rl.Descriptors {
			refRef := r.SetDigest(desc.Digest.String())
			if err := rc.ManifestDelete(ctx, refRef); err != nil {
				slog.Warn("failed to delete referrer", "digest", desc.Digest.String(), "error", err)
			}
		}
	}

	// Delete the manifest by digest
	digestRef := r.SetDigest(m.GetDescriptor().Digest.String())
	if err := rc.ManifestDelete(ctx, digestRef); err != nil {
		return fmt.Errorf("delete manifest: %w", err)
	}

	// Delete the tag
	if err := rc.TagDelete(ctx, r); err != nil {
		slog.Warn("failed to delete tag", "error", err)
	}

	return nil
}

func runList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	image := fs.String("image", "", "image reference")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *image == "" {
		return fmt.Errorf("-image is required")
	}

	r, err := ref.New(*image)
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}

	rc := regclient.New(
		regclient.WithDockerCreds(),
		regclient.WithDockerCerts(),
	)
	defer rc.Close(ctx, r)

	rl, err := rc.ReferrerList(ctx, r)
	if err != nil {
		return fmt.Errorf("list referrers: %w", err)
	}

	if len(rl.Descriptors) == 0 {
		slog.Info("no referrers found")
		return nil
	}

	slog.Info("listing referrers", "image", *image, "count", len(rl.Descriptors))
	for _, desc := range rl.Descriptors {
		at := desc.ArtifactType
		if at == "" {
			at = desc.MediaType
		}
		slog.Info("referrer", "type", at, "digest", desc.Digest.String(), "size", desc.Size)
	}

	return nil
}
