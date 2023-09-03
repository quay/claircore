package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/scheme"
	"github.com/regclient/regclient/scheme/ocidir"
	oci "github.com/regclient/regclient/types/oci/v1"
	"github.com/regclient/regclient/types/ref"

	"github.com/quay/claircore/test/integration"
)

func lookupCaller(t *testing.T) string {
	const module = `github.com/quay/claircore/`
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		t.Fatal("unable to get caller")
	}
	info := runtime.FuncForPC(pc)
	name := info.Name()
	idx := strings.LastIndexByte(name, '.')
	if idx == -1 {
		t.Fatalf("weird name: %q", name)
	}
	return strings.TrimPrefix(name[:idx], module)
}

var (
	// Alternatively, use ghcr.io ?
	Registry  = `quay.io`
	Namespace = `projectquay`
	Tag       = `latest`
)

const (
	// VulnerabilitiesType is the Artifact Type that indicates this artifact should
	// be used to build a vulnerability database.
	//
	// The "yolo" type indicates this should be passed into an unknown,
	// per-package processing function. The type is functionally
	// "application/octet-stream".
	VulnerabilitiesType = `application/vnd.claircore-test.vulnerabilities.yolo.layer.v1`
	// VulnerabilitiesType is the Artifact Type that indicates this artifact should
	// be used to build an advisory database.
	//
	// The blob should be of type "application/zip". The artifact may indicate
	// via TBD named annotations what Matcher is expected to handle the data.
	AdvisoriesType = `application/vnd.claircore-test.advisories.zip.layer.v1`
	// VerifyType is the Artifact Type that indicates ..
	VerifyType = `application/vnd.claircore-test.verify.jsonpatch.layer.v1`

	MatcherConfigType = `application/vnd.claircore-test.matcher.configuration.layer.v1+json`
	UpdaterConfigType = `application/vnd.claircore-test.updater.configuration.layer.v1+json`
	IndexerConfigType = `application/vnd.claircore-test.indexer.configuration.layer.v1+json`
)

// Fetch ...
func Fetch[V Value, K Kind[V]](ctx context.Context, t *testing.T) []V {
	t.Helper()
	repo := lookupCaller(t)
	dir := filepath.Join(integration.PackageCacheDir(t), "fixtures")
	if err := os.Mkdir(dir, 0755); err != nil && !errors.Is(err, fs.ErrExist) {
		t.Fatal(err)
	}
	sys := regclient.NewDirFS(dir)
	var elem K

	c := regclient.New(
		regclient.WithFS(sys),
		regclient.WithDockerCreds(),
	)
	tgt, err := ref.New("ocidir://" + Tag)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("FetchFixtures", func(t *testing.T) {
		integration.Skip(t)
		name := fmt.Sprintf("%s/%s/%s:%s", Registry, Namespace, repo, Tag)
		t.Logf("pulling fixtues referencing %q", name)
		remote, err := ref.New(name)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx, remote)
		if err := c.ImageCopy(ctx, remote, tgt); err != nil {
			t.Error(err)
		}
	})

	switch _, err := fs.Stat(sys, path.Join(Tag, "oci-layout")); {
	case errors.Is(err, nil): // OK
	case errors.Is(err, fs.ErrNotExist):
		t.Skip("skipping integration test: need integration tag at least once to populate fixtures")
	default:
		t.Fatalf("unexpected error with local files: %v", err)
	}

	at := elem.ArtifactType()
	list, err := c.ReferrerList(ctx, tgt, scheme.WithReferrerAT(at))
	if err != nil {
		t.Fatal(err)
	}
	if list.IsEmpty() {
		t.Logf("no manifests of type %q for %s", at, tgt.CommonName())
		return nil
	}

	out := make([]V, len(list.Descriptors))
	local := ocidir.New(ocidir.WithFS(sys))
	for i, d := range list.Descriptors {
		rd, err := c.BlobGet(ctx, tgt, d)
		if err != nil {
			t.Fatalf("error fetching blob: %v", err)
		}
		t.Logf("found descriptor: %v", d)
		// Don't worry too much about the Reader; all tests are transitory, man.
		var m oci.Manifest
		if err := json.NewDecoder(rd).Decode(&m); err != nil {
			t.Fatalf("unexpected error decoding descriptor data: %v", err)
		}
		rd.Close()
		var k K = &out[i]
		if err := k.Load(ctx, t, dir, local, tgt, &m); err != nil {
			t.Fatalf("tk: %v", err)
		}
	}

	return out
}
