package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/quay/claircore"
	"github.com/regclient/regclient/scheme/ocidir"
	"github.com/regclient/regclient/types"
	oci "github.com/regclient/regclient/types/oci/v1"
	"github.com/regclient/regclient/types/ref"
)

const artifactTmpl = `application/vnd.claircore.test-fixture.%s.config.v1`

type Kind[T Value] interface {
	*T
	// Load takes an OCIDir so that we can _know_ the path of blobs.
	Load(context.Context, *testing.T, string, *ocidir.OCIDir, ref.Ref, *oci.Manifest) error
	ArtifactType() string
}

type Value interface {
	Indexer | Matcher | Updater | MatcherFlow | Integration
}

var ErrBadArtifactType = errors.New("bad artifact type")

type testTransform struct {
	p *jsonpatch.Patch
}

var opTest = json.RawMessage(`"test"`)

func (t *testTransform) UnmarshalJSON(b []byte) error {
	var op jsonpatch.Operation
	if err := json.Unmarshal(b, &op); err != nil {
		return err
	}
	op["op"] = &opTest
	*t.p = append(*t.p, op)
	return nil
}

type Indexer struct {
	Manifest claircore.Manifest
	Verify   jsonpatch.Patch
}

func (*Indexer) ArtifactType() string { return fmt.Sprintf(artifactTmpl, `indexer`) }
func (i *Indexer) Load(ctx context.Context, t *testing.T, root string, dir *ocidir.OCIDir, r ref.Ref, m *oci.Manifest) error {
	if m.ArtifactType != i.ArtifactType() {
		return ErrBadArtifactType
	}
	for _, l := range m.Layers {
		switch l.ArtifactType {
		case types.MediaTypeOCI1Manifest:
			d := l.Digest.String()
			i.Manifest.Hash = claircore.MustParseDigest(d)
			r := r
			r.Tag = ""
			r.Digest = d
			om, err := dir.ManifestGet(ctx, r)
			if err != nil {
				return err
			}
			ls, err := om.GetLayers()
			if err != nil {
				return err
			}
			for _, d := range ls {
				i.Manifest.Layers = append(i.Manifest.Layers,
					&claircore.Layer{
						Hash: claircore.MustParseDigest(d.Digest.String()),
						URI: (&url.URL{
							Scheme: "file",
							Opaque: filepath.Join(root, "blobs", d.Digest.Algorithm().String(), d.Digest.Encoded()),
						}).String(),
					})
			}
		case VerifyType:
			rc, err := dir.BlobGet(ctx, r, l)
			if err != nil {
				return err
			}
			defer rc.Close()
			if err := json.NewDecoder(rc).Decode(&testTransform{&i.Verify}); err != nil {
				return err
			}
		default: // Skip
			t.Logf("skipping artifact: %s", l.ArtifactType)
		}
	}
	return nil
}

type Matcher struct{}

func (*Matcher) ArtifactType() string { return fmt.Sprintf(artifactTmpl, `matcher`) }
func (ma *Matcher) Load(ctx context.Context, t *testing.T, root string, dir *ocidir.OCIDir, r ref.Ref, m *oci.Manifest) error {
	panic("TODO: implement")
}

type Updater struct{}

func (*Updater) ArtifactType() string { return fmt.Sprintf(artifactTmpl, `updater`) }
func (u *Updater) Load(ctx context.Context, t *testing.T, root string, dir *ocidir.OCIDir, r ref.Ref, m *oci.Manifest) error {
	panic("TODO: implement")
}

type MatcherFlow struct{}

func (*MatcherFlow) ArtifactType() string { return fmt.Sprintf(artifactTmpl, `matcher-flow`) }
func (mf *MatcherFlow) Load(ctx context.Context, t *testing.T, root string, dir *ocidir.OCIDir, r ref.Ref, m *oci.Manifest) error {
	panic("TODO: implement")
}

type Integration struct{}

func (*Integration) ArtifactType() string { return fmt.Sprintf(artifactTmpl, `integration`) }
func (i *Integration) Load(ctx context.Context, t *testing.T, root string, dir *ocidir.OCIDir, r ref.Ref, m *oci.Manifest) error {
	panic("TODO: implement")
}

// Compile-time type checks:
var (
	_ func(context.Context, *testing.T) []Indexer     = Fetch[Indexer]
	_ func(context.Context, *testing.T) []Matcher     = Fetch[Matcher]
	_ func(context.Context, *testing.T) []Updater     = Fetch[Updater]
	_ func(context.Context, *testing.T) []MatcherFlow = Fetch[MatcherFlow]
	_ func(context.Context, *testing.T) []Integration = Fetch[Integration]
)
