package aws

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/quay/alas"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	amazonLinux1Mirrors = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	amazonLinux2Mirrors = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
	repoDataPath        = "/repodata/repomd.xml"
	updatesPath         = "/repodata/updateinfo.xml.gz"
)

var logger = log.With().Str("component", "aws-alas-client").Logger()

// Client is an http for accessing ALAS mirrors.
type Client struct {
	c       *http.Client
	mirrors []*url.URL
	logger  zerolog.Logger
}

func NewClient(release Release) (*Client, error) {
	client := &Client{
		c:       &http.Client{},
		mirrors: []*url.URL{},
		logger:  log.With().Str("component", "aws-alas-client").Str("release", string(release)).Logger(),
	}
	err := client.getMirrors(release)
	return client, err
}

// RepoMD returns a alas.RepoMD containing sha256 information of a repositories contents
func (c *Client) RepoMD() (alas.RepoMD, error) {
	for _, mirror := range c.mirrors {
		path := path.Join(mirror.String(), repoDataPath)
		uu, err := url.Parse(path)
		if err != nil {
			return alas.RepoMD{}, fmt.Errorf("failed to parse url: %v", err)
		}

		c.logger.Debug().Msgf("attempting repomd download from mirror %v", path)
		resp, err := c.c.Get(uu.String())
		if err != nil {
			c.logger.Error().Msgf("failed to retrieve repomd from mirror %v", path)
			continue
		}
		if (resp.StatusCode <= 199) || (resp.StatusCode >= 300) {
			c.logger.Error().Msgf("received bad status code %v when retrieving repomd at mirror %v", resp.StatusCode, path)
			continue
		}

		repoMD := alas.RepoMD{}
		err = xml.NewDecoder(resp.Body).Decode(&repoMD)
		if err != nil {
			c.logger.Error().Msgf("failed to xml unmarshall repodm at mirror %v: %v", path, err)
			continue
		}

		c.logger.Info().Msgf("successfully retrieved repomd data from mirror %v", path)
		return repoMD, nil
	}

	c.logger.Error().Msg("exhausted all mirrors requesting repomd")
	return alas.RepoMD{}, fmt.Errorf("all mirrors failed to retrieve repo metadata")
}

// Updates returns the *http.Response of the first mirror to establish a connection
func (c *Client) Updates() (*http.Response, error) {
	for _, mirror := range c.mirrors {
		path := path.Join(mirror.String(), updatesPath)

		resp, err := c.c.Get(path)
		if err != nil {
			c.logger.Error().Msgf("failed to make request for updates to mirror %v: %v", path, err)
			continue
		}
		if (resp.StatusCode <= 199) || (resp.StatusCode >= 300) {
			c.logger.Error().Msgf("received bad status code %v when retrieving updates at mirror %v", err, path)
			continue
		}

		c.logger.Info().Msgf("successfully retrieved updates from mirror %v", path)
		return resp, nil
	}

	c.logger.Error().Msg("exhausted all mirrors requesting updates")
	return nil, fmt.Errorf("all update_info mirrors failed to return a response")
}

func (c *Client) getMirrors(release Release) error {
	var (
		resp *http.Response
		err  error
	)

	switch release {
	case Linux1:
		resp, err = c.c.Get(amazonLinux1Mirrors)
	case Linux2:
		resp, err = c.c.Get(amazonLinux2Mirrors)
	}

	if err != nil {
		c.logger.Error().Msgf("failed to make request for %v mirrors: %v", release, err)
		return fmt.Errorf("failed to make request for %v mirrors: %v", release, err)
	}

	if (resp.StatusCode <= 199) || (resp.StatusCode >= 300) {
		c.logger.Error().Msgf("http error %v when retrieving mirror list: %v", resp.StatusCode, resp.Status)
		return fmt.Errorf("http error %v when retrieving mirror list: %v", resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.logger.Error().Msgf("failed to read http body: %v", err)
		return fmt.Errorf("failed to read http body: %v", err)
	}
	urls := strings.Split(string(body), "\n")

	for _, u := range urls {
		uu, err := url.Parse(u)
		if err != nil {
			c.logger.Error().Msgf("could not parse returned mirror %v as URL: %v", u, err)
			return fmt.Errorf("could not parse returned mirror %v as URL: %v", u, err)
		}
		c.mirrors = append(c.mirrors, uu)
	}

	c.logger.Info().Msgf("successfully got list of mirrors %v", c.mirrors)
	return nil
}
