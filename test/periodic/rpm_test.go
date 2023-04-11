package periodic

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/rpm"
	"github.com/quay/claircore/test/fetch"
	"github.com/quay/claircore/test/rpmtest"
)

// TestRPMSpotCheck searches against the production Hydra API to find published
// container images, then fetches and indexes the manifest and compares it to
// the published RPM manifest for the image.
func TestRPMSpotCheck(t *testing.T) {
	ctx := context.Background()
	// This is the URL for our search query. Needs to get Solr search parameters
	// added to the RawQuery member.
	query := url.URL{
		Scheme: "https",
		Host:   "access.redhat.com",
		Path:   "/hydra/rest/search/kcs",
	}
	for _, pair := range [][2]string{
		{"ubi", "repository:ubi?/ubi*"},
		{"s2i", "repository:ubi?/s2i-*"},
		{"nodejs", "repository:ubi?/nodejs*"},
	} {
		query := query
		// This is Solr search values. Need to add an `fq` and `q` parameter to use.
		qv := url.Values{
			"redhat_client": {"claircore-tests"},
			"fq": {
				`documentKind:"ContainerRepository"`,
				`-release_catagories:"Deprecated"`,
			},
			"fl":   {"id,repository,registry,parsed_data_layers"},
			"rows": {"500"},
		}
		qv.Set("q", pair[0])
		qv.Add("fq", pair[1])
		query.RawQuery = qv.Encode()
		t.Run(pair[0], func(t *testing.T) {
			t.Parallel()
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
			var buf bytes.Buffer
			if err := json.NewDecoder(io.TeeReader(res.Body, &buf)).Decode(&searchRes); err != nil {
				t.Error(err)
			}
			defer func() {
				if !t.Failed() {
					return
				}
				t.Logf("search response:\t%q", buf.String())
			}()
			dir := t.TempDir()
			for _, d := range searchRes.Response.Docs {
				t.Run(d.Repository, d.Run(dir))
			}
		})
	}
}

type hydraResponse struct {
	Response struct {
		Docs []hydraDoc `json:"docs"`
	} `json:"response"`
}

type hydraDoc struct {
	ID         string             `json:"id"`
	Repository string             `json:"repository"`
	Registry   string             `json:"registry"`
	Layers     []claircore.Digest `json:"parsed_data_layers"`
}

type imageInfo struct {
	Links imageInfoLinks `json:"_links"`
}

type imageInfoLinks struct {
	Images      link `json:"images"`
	RpmManifest link `json:"rpm_manifest"`
}

type link struct {
	Href string `json:"href"`
}

type imagesResponse struct {
	Data []struct {
		ID     string         `json:"_id"`
		Links  imageInfoLinks `json:"_links"`
		Parsed struct {
			Layers []claircore.Digest `json:"layers"`
		} `json:"parsed_data"`
	} `json:"data"`
}

func (doc hydraDoc) Run(dir string) func(*testing.T) {
	root := url.URL{
		Scheme: "https",
		Host:   "catalog.redhat.com",
		Path:   "/api/containers/",
	}
	return func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(context.Background(), t)
		try := 1

	Retry:
		fetchURL, err := root.Parse(path.Join("/api/containers/", "v1/repositories/id/", doc.ID))
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("accept", "application/json")
		res, err := pkgClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		switch res.StatusCode {
		case http.StatusOK:
		case http.StatusServiceUnavailable:
			if try == 10 {
				t.Fatal("too many retries")
			}
			time.Sleep(time.Duration(try*2) * time.Second)
			try++
			goto Retry
		default:
			t.Fatalf("unexpected response to %q: %s", fetchURL.String(), res.Status)
		}
		buf := &bytes.Buffer{}
		var info imageInfo
		if err := json.NewDecoder(io.TeeReader(res.Body, buf)).Decode(&info); err != nil {
			t.Fatalf("%s: %v", fetchURL.String(), err)
		}
		defer logResponse(t, res.Request.URL.Path, buf)()

		imageURL, err := root.Parse(path.Join("/api/containers/", info.Links.Images.Href))
		if err != nil {
			t.Fatal(err)
		}
		imageURL.RawQuery = (url.Values{
			"page_size": {"1"},
			"page":      {"0"},
			"exclude":   {"data.repositories.comparison.advisory_rpm_mapping,data.brew,data.cpe_ids,data.top_layer_id"},
			"filter":    {"deleted!=true"},
		}).Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, imageURL.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("accept", "application/json")
		res, err = pkgClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("unexpected response to %q: %s", imageURL.String(), res.Status)
		}
		buf = &bytes.Buffer{}
		var image imagesResponse
		if err := json.NewDecoder(io.TeeReader(res.Body, buf)).Decode(&image); err != nil {
			t.Fatalf("%s: %v", imageURL.String(), err)
		}
		defer logResponse(t, res.Request.URL.Path, buf)()

		manifestURL, err := fetchURL.Parse(path.Join("/api/containers/", image.Data[0].Links.RpmManifest.Href))
		if err != nil {
			t.Fatal(err)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, manifestURL.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("accept", "application/json")
		res, err = pkgClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("unexpected response to %q: %s", manifestURL.String(), res.Status)
		}

		buf = &bytes.Buffer{}
		want := rpmtest.PackagesFromRPMManifest(t, io.TeeReader(res.Body, buf))
		defer logResponse(t, res.Request.URL.Path, buf)()

		s := &rpm.Scanner{}
		var got []*claircore.Package
		var which claircore.Digest
		for _, ld := range image.Data[0].Parsed.Layers {
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

func logResponse(t *testing.T, u string, b *bytes.Buffer) func() {
	return func() {
		if !t.Failed() {
			return
		}
		t.Logf("%s response:\t%q", u, b.String())
	}
}
