package periodic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/rpm"
	"github.com/quay/claircore/test/fetch"
	"github.com/quay/claircore/test/rpmtest"
)

func TestRPMSpotCheck(t *testing.T) {
	ctx := context.Background()
	query := url.URL{
		Scheme: "https",
		Host:   "access.redhat.com",
		Path:   "/hydra/rest/search/kcs",
		RawQuery: url.Values{
			"redhat_client": {"claircore-tests"},
			"fq": {
				"documentKind:ContainerRepository",
				"repository:ubi?/ubi*",
			},
			"fl":   {"container_image_id,repository,registry,parsed_data_layers"},
			"rows": {"20"},
			"q":    {"ubi"},
		}.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, query.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("accept", "application/json")
	res, err := pkgClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpect response to %q: %s", query.String(), res.Status)
	}
	t.Logf("%s: %s", query.String(), res.Status)
	var searchRes hydraResponse
	if err := json.NewDecoder(res.Body).Decode(&searchRes); err != nil {
		t.Error(err)
	}
	//t.Log(searchRes)
	dir := t.TempDir()
	for _, d := range searchRes.Response.Docs {
		t.Run(d.Repository, d.Run(dir))
	}
}

type hydraResponse struct {
	Response struct {
		Docs []hydraDoc `json:"docs"`
	} `json:"response"`
}

type hydraDoc struct {
	ID         string             `json:"container_image_id"`
	Repository string             `json:"repository"`
	Registry   string             `json:"registry"`
	Layers     []claircore.Digest `json:"parsed_data_layers"`
}

func (doc hydraDoc) Run(dir string) func(*testing.T) {
	manifestURL := url.URL{
		Scheme: "https",
		Host:   "catalog.redhat.com",
		Path:   path.Join("/api/containers/v1/images/id", doc.ID, "rpm-manifest"),
	}
	return func(t *testing.T) {
		ctx := zlog.Test(context.Background(), t)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("accept", "application/json")
		res, err := pkgClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("unexpected response to %q: %s", manifestURL.String(), res.Status)
		}
		want := rpmtest.PackagesFromRPMManifest(t, res.Body)

		s := &rpm.Scanner{}
		var got []*claircore.Package
		var which claircore.Digest
		for _, ld := range doc.Layers {
			n, err := fetch.Layer(ctx, t, pkgClient, doc.Registry, doc.Repository, ld, fetch.IgnoreIntegration)
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			l := claircore.Layer{Hash: ld}
			l.SetLocal(n.Name())

			pkgs, err := s.Scan(ctx, &l)
			if err != nil {
				t.Error(err)
			}
			if len(pkgs) >= len(want) {
				got = pkgs
				which = ld
				break
			}
		}
		t.Logf("found %d packages in %v", len(got), which)
		t.Logf("comparing to %d packages in manifest %s", len(want), doc.ID)

		if !cmp.Equal(got, want, rpmtest.Options) {
			t.Error(cmp.Diff(got, want, rpmtest.Options))
		}
	}
}
