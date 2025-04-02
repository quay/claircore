package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/tools/txtar"

	"github.com/quay/claircore/test/redhat/catalog"
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
	repo, err := TeeJSONRequest[catalog.Repository](ctx, c.c, ar, repoURL)
	if err != nil {
		return err
	}

	imagesURL := catalogRoot.JoinPath(repo.Links["images"].Href)
	imagesURL.RawQuery = imagesQueryParams().Encode()
	images, err := TeeJSONRequest[catalog.Images](ctx, c.c, ar, imagesURL)
	if err != nil {
		return err
	}

	arch := map[string]struct{}{}
	for _, image := range images.Data {
		a := image.Archtecture
		if _, ok := arch[a]; ok {
			slog.Log(ctx, levelTrace, "already have image for arch, skipping", "arch", a)
			continue
		}
		arch[a] = struct{}{}
		manifestURL := catalogRoot.JoinPath(image.Links["rpm_manifest"].Href)
		_, err := TeeJSONRequest[json.RawMessage](ctx, c.c, ar, manifestURL)
		if err != nil {
			return err
		}
	}
	if len(arch) < 4 {
		slog.WarnContext(ctx, "may not have images for all architectures", "got", maps.Keys(arch))
	}

	return nil
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
	// Request a few more than 4 so we will almost certainly catch every architecture.
	v.Set("page_size", "6")
	v.Set("filter", "deleted!=true")
	v.Set("sort_by", "creation_date[asc]")
	return v
}
