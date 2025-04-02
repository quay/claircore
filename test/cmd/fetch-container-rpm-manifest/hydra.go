package main

import (
	"context"
	"maps"
	"net/http"
	"net/url"

	"github.com/quay/claircore"
	"golang.org/x/tools/txtar"
)

// HydraClient is a helper for querying the "hydra" search service.
type HydraClient struct {
	c *http.Client
}

// Search for container repositories for with the search term "fq".
//
// Fetched URLs and response bodies are transcribed into "ar".
func (h *HydraClient) Search(ctx context.Context, ar *txtar.Archive, fq string) ([]HydraDoc, error) {
	WriteHeader(ar, "search-term", fq)

	v := maps.Clone(hydraQuery)
	v.Add("fq", fq)
	u := hydraRoot
	u.RawQuery = v.Encode()

	searchRes, err := TeeJSONRequest[HydraResponse](ctx, h.c, ar, &u)
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

// HydraResponse is the top-level response from the hydra service.
//
// This has just enough structure to get at the needed data.
type HydraResponse struct {
	Response struct {
		Docs []HydraDoc `json:"docs"`
	} `json:"response"`
}

// HydraDoc is an individual search result.
//
// This has just enough structure to get at the needed data.
type HydraDoc struct {
	ID         string             `json:"id"`
	Repository string             `json:"repository"`
	Registry   string             `json:"registry"`
	Layers     []claircore.Digest `json:"parsed_data_layers"`
}
