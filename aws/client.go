package aws

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/quay/alas"
)

const (
	amazonLinux1Mirrors = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	amazonLinux2Mirrors = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
	repoDataPath        = "/repodata/repomd.xml"
	updatesPath         = "/repodata/updateinfo.xml.gz"
)

// Client is an http for accessing ALAS mirrors.
type Client struct {
	c       *http.Client
	mirrors []*url.URL
}

func NewClient(release Releases) (*Client, error) {
	client := &Client{
		c:       &http.Client{},
		mirrors: []*url.URL{},
	}
	err := client.getMirrors(release)
	return client, err
}

// RepoMD returns a alas.RepoMD containing sha256 information of a repositories contents
func (c *Client) RepoMD() (alas.RepoMD, error) {
	for _, mirror := range c.mirrors {
		mirror.Path = path.Join(mirror.Path, repoDataPath)

		resp, err := c.c.Get(mirror.String())
		if err != nil {
			log.Printf("failed ")
			continue
		}
		if (resp.StatusCode <= 199) && (resp.StatusCode >= 300) {
			continue
		}

		repoMD := alas.RepoMD{}
		err = xml.NewDecoder(resp.Body).Decode(&repoMD)
		if err != nil {
			continue
		}

		return repoMD, nil
	}
	return alas.RepoMD{}, fmt.Errorf("all mirrors failed to retrieve repo metadata")
}

// Updates returns the *http.Response of the first mirror to establish a connection
func (c *Client) Updates() (*http.Response, error) {
	for _, mirror := range c.mirrors {
		mirror.Path = path.Join(mirror.Path, updatesPath)

		resp, err := c.c.Get(mirror.String())
		if err != nil {
			log.Printf("failed ")
			continue
		}
		if (resp.StatusCode <= 199) && (resp.StatusCode >= 300) {
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("all update_info mirrors failed to return a response")
}

func (c *Client) getMirrors(release Releases) error {
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
		return fmt.Errorf("failed to make request for %v mirrors: %v", release, err)
	}

	if (resp.StatusCode <= 199) && (resp.StatusCode >= 300) {
		return fmt.Errorf("http error %v when retrieving mirror list: %v", resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read http body: %v", err)
	}
	urls := strings.Split(string(body), "\n")

	for _, u := range urls {
		uu, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("could not parse returned mirror %v as URL: %v", u, err)
		}
		c.mirrors = append(c.mirrors, uu)
	}

	return nil
}
