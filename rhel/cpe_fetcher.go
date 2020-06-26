package rhel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/rs/zerolog"
)

type containerImages struct {
	Images []containerImage `json:"data"`
}
type containerImage struct {
	CPE        []string   `json:"cpe_ids"`
	ParsedData parsedData `json:"parsed_data"`
}
type parsedData struct {
	Architecture string  `json:"architecture"`
	Labels       []label `json:"labels"`
}
type label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ContainerAPI gets container metadata from Red Hat's API.
type containerAPI struct {
	client *http.Client
	root   *url.URL
}

// GetCPEs fetches CPE information for given build from Red Hat Container API.
func (c *containerAPI) GetCPEs(ctx context.Context, nvr, arch string) ([]string, error) {
	log := zerolog.Ctx(ctx).With().Logger()
	uri, err := c.root.Parse(path.Join("v1/images/nvr/", nvr))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("uri", uri.String()).
		Msg("making container API request")
	res, err := c.client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		var b strings.Builder
		if _, err := io.Copy(&b, res.Body); err != nil {
			log.Warn().Err(err).Msg("additional error while reading response")
		} else {
			log.Warn().Str("response", b.String()).Msg("received error response")
		}
		return nil, fmt.Errorf("rhel: unexpected response: %d %s", res.StatusCode, res.Status)
	}

	var ci containerImages
	if err := json.NewDecoder(res.Body).Decode(&ci); err != nil {
		return nil, err
	}
	for _, image := range ci.Images {
		for _, label := range image.ParsedData.Labels {
			if label.Name == "architecture" {
				if label.Value == arch {
					return image.CPE, nil
				}
			}
		}
	}
	return nil, nil
}
