package main

import (
	"context"
	"maps"
	"net/http"
	"net/url"

	"golang.org/x/tools/txtar"

	"github.com/quay/claircore/test/redhat/hydra"
)

// HydraClient is a helper for querying the "hydra" search service.
type HydraClient struct {
	c *http.Client
}

// Search for container repositories for with the search term "fq".
//
// Fetched URLs and response bodies are transcribed into "ar".
func (h *HydraClient) Search(ctx context.Context, ar *txtar.Archive, fq string) ([]hydra.Doc, error) {
	WriteHeader(ar, "search-term", fq)

	v := maps.Clone(hydraQuery)
	v.Add("fq", fq)
	u := hydraRoot
	u.RawQuery = v.Encode()

	searchRes, err := TeeJSONRequest[hydra.Response](ctx, h.c, ar, &u)
	if err != nil {
		return nil, err
	}
	return searchRes.Response.Docs, nil
}

var (
	// HydraRoot is the URL used to build requests.
	hydraRoot = url.URL{
		Scheme: "https",
		Host:   "access.redhat.com",
		Path:   "/hydra/rest/search/kcs",
	}
	// HydraQuery is the static part of hydra queries.
	hydraQuery = url.Values{
		"redhat_client": {"claircore/fetch-container-rpm-manifest"},
		"fq": {
			`documentKind:"ContainerRepository"`,
			`-eol_date:[* TO NOW]`,
		},
		"fl":   {"id,repository,registry,parsed_data_layers"},
		"rows": {"10"},
		"q":    {"*"},
	}
)
