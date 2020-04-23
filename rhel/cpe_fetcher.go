package rhel

import (
	"crypto/tls"
	"encoding/json"
	"net/http"

	"github.com/quay/claircore/pkg/envutil"
	"github.com/rs/zerolog/log"
)

var apiURL = envutil.GetEnv("CONTAINER_API_URL", "https://catalog.redhat.com/api/containers")
var apiCertPath = envutil.GetEnv("CONTAINER_API_CERT_PATH", "")

type containerImages struct {
	Images []containerImage `json:"data"`
}

type containerImage struct {
	CPE        []string `json:"cpe_ids"`
	ParsedData struct {
		Architecture string `json:"architecture"`
		Labels       []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"labels"`
	} `json:"parsed_data"`
}

// ContainerAPICpeFetcher gets container metadata from Red Hat's API
type ContainerAPICpeFetcher struct{}

// GetCPEs fetches CPE information for given build from Red Hat Container API
func (fetcher *ContainerAPICpeFetcher) GetCPEs(nvr, arch string) (cpes []string, err error) {
	transport := http.Transport{}
	if apiCertPath != "" {

		clientCert, err := tls.LoadX509KeyPair(apiCertPath, apiCertPath)
		if err != nil {
			return []string{}, err
		}
		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{clientCert},
		}

		transport = http.Transport{
			TLSClientConfig: &tlsConfig,
		}
	}

	client := http.Client{
		Transport: &transport,
	}
	url := apiURL + "/v1/images/nvr/" + nvr
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return
	}

	var ci containerImages
	err = json.NewDecoder(resp.Body).Decode(&ci)
	if err != nil {
		log.Error().Msg("Unexpected format:" + url)
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
	return
}
