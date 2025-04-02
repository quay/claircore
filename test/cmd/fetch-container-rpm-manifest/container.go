package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/tools/txtar"
)

// CatalogClient is a helper for querying the Container Catalog API.
type CatalogClient struct {
	c *http.Client
}

// CatalogRoot is the URL used to build requests.
var catalogRoot = url.URL{
	Scheme: "https",
	Host:   "catalog.redhat.com",
	Path:   "/api/containers/",
}

// FetchManifest fetches RPM manifests for images in the repository "id".
//
// Only the first image for a given architecture is processed.
//
// Fetched URLs and response bodies are transcribed into "ar".
func (c *CatalogClient) FetchManifest(ctx context.Context, ar *txtar.Archive, id string) error {
	repoURL := catalogRoot.JoinPath("v1", "repositories", "id", id)
	repo, err := TeeJSONRequest[CatalogRepository](ctx, c.c, ar, repoURL)
	if err != nil {
		return err
	}

	imagesURL := catalogRoot.JoinPath(repo.Links["images"].Href)
	imagesURL.RawQuery = imagesQueryParams().Encode()
	images, err := TeeJSONRequest[CatalogRepositoryImages](ctx, c.c, ar, imagesURL)
	if err != nil {
		return err
	}

	arch := map[string]struct{}{}
	for _, image := range images.Data {
		if _, ok := arch[image.Arch]; ok {
			slog.Log(ctx, levelTrace, "already have image for arch, skipping", "arch", image.Arch)
			continue
		}
		arch[image.Arch] = struct{}{}
		manifestURL := catalogRoot.JoinPath(image.Links["rpm_manifest"].Href)
		_, err := TeeJSONRequest[json.RawMessage](ctx, c.c, ar, manifestURL)
		if err != nil {
			return err
		}
	}

	return nil
}

// CatalogRepository is the response from fetching a repository from the catalog.
//
// This has just enough structure to get at the needed data.
type CatalogRepository struct {
	Links map[string]Link `json:"_links"`
}

// Link is a hypermedia pointer.
type Link struct {
	Href string `json:"href"`
}

// CatalogRepositoryImages is the top-level response for listing images
// belonging to a repository.
//
// This has just enough structure to get at the needed data.
type CatalogRepositoryImages struct {
	Data []CatalogImage `json:"data"`
}

// CatalogImage is a single image in the container catalog.
//
// This has just enough structure to get at the needed data.
type CatalogImage struct {
	ID     string                 `json:"_id"`
	Links  map[string]Link        `json:"_links"`
	Arch   string                 `json:"architecture"`
	Parsed CatalogImageParsedData `json:"parsed_data"`
}

// CatalogImageParsedData is information seemingly parsed out of the image
// directly.
//
// This has just enough structure to get at the needed data.
type CatalogImageParsedData struct {
	Layers []string `json:"layers"`
}

func imagesQueryParams() url.Values {
	v := make(url.Values)
	fields := []string{
		"brew",
		"certified",
		"container_grades",
		"content_sets",
		"cpe_ids",
		"docker_image_id",
		"freshness_grades",
		"parsed_data.command",
		"parsed_data.comment",
		"parsed_data.docker_version",
		"parsed_data.env_variables",
		"parsed_data.labels",
		"parsed_data.ports",
		"parsed_data.size",
		"parsed_data.uncompressed_size_bytes",
		"parsed_data.user",
		"raw_config",
		"repositories",
		"sum_layer_size_bytes",
		"top_layer_id",
		"uncompressed_top_layer_id",
	}
	for i := range fields {
		fields[i] = `data.` + fields[i]
	}
	v.Set("exclude", strings.Join(fields, ","))
	v.Set("page", "0")
	v.Set("page_size", "10")
	v.Set("filter", "deleted!=true")
	return v
}
