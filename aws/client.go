package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/quay/alas"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore/pkg/tmp"
)

const (
	repoDataPath     = "/repodata/repomd.xml"
	updatesPath      = "/repodata/updateinfo.xml.gz"
	defaultOpTimeout = 15 * time.Second
)

// overwritten in tests
var (
	amazonLinux1Mirrors = "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"
	amazonLinux2Mirrors = "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"
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
	tctx, cancel := context.WithTimeout(context.Background(), defaultOpTimeout)
	defer cancel()
	err := client.getMirrors(tctx, release)
	return client, err
}

// RepoMD returns a alas.RepoMD containing sha256 information of a repositories contents
func (c *Client) RepoMD(ctx context.Context) (alas.RepoMD, error) {
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, repoDataPath)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			c.logger.Error().Msgf("failed to make request object: %v %v", m, err)
			continue
		}

		c.logger.Debug().Msgf("attempting repomd download from mirror %v", m)
		resp, err := c.c.Do(req)
		if err != nil {
			c.logger.Error().Msgf("failed to retrieve repomd from mirror %v: %v", m, err)
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			c.logger.Error().Msgf("repoMD mirror %v got unexpected HTTP response: %d (%s)", m, resp.StatusCode, resp.Status)
			continue
		}

		repoMD := alas.RepoMD{}
		err = xml.NewDecoder(resp.Body).Decode(&repoMD)
		if err != nil {
			c.logger.Error().Msgf("failed to xml unmarshall repodm at mirror %v: %v", m, err)
			continue
		}

		c.logger.Info().Msgf("successfully retrieved repomd data from mirror %v", m)
		return repoMD, nil
	}

	c.logger.Error().Msg("exhausted all mirrors requesting repomd")
	return alas.RepoMD{}, fmt.Errorf("all mirrors failed to retrieve repo metadata")
}

// Updates returns the *http.Response of the first mirror to establish a connection
func (c *Client) Updates(ctx context.Context) (io.ReadCloser, error) {
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, updatesPath)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			c.logger.Error().Msgf("failed to make request object: %v %v", m, err)
			continue
		}

		tf, err := tmp.NewFile("", "")
		if err != nil {
			c.logger.Error().Msgf("failed to make request for updates to mirror %v: %v", m, err)
		}

		resp, err := c.c.Do(req)
		if err != nil {
			c.logger.Error().Msgf("failed to make request for updates to mirror %v: %v", m, err)
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			c.logger.Error().Msgf("updates mirror %v got unexpected HTTP response: %d (%s)", m, resp.StatusCode, resp.Status)
			tf.Close()
			continue
		}

		if _, err := io.Copy(tf, resp.Body); err != nil {
			tf.Close()
			return nil, err
		}
		if o, err := tf.Seek(0, io.SeekStart); err != nil || o != 0 {
			tf.Close()
			return nil, err
		}

		c.logger.Info().Msgf("successfully retrieved updates from mirror %v", m)
		return tf, nil
	}

	c.logger.Error().Msg("exhausted all mirrors requesting updates")
	return nil, fmt.Errorf("all update_info mirrors failed to return a response")
}

func (c *Client) getMirrors(ctx context.Context, release Release) error {
	var (
		req *http.Request
		err error
	)

	switch release {
	case Linux1:
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, amazonLinux1Mirrors, nil)
	case Linux2:
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, amazonLinux2Mirrors, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to create request for mirror list %v : %v", amazonLinux1Mirrors, err)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.logger.Error().Msgf("failed to make request for %v mirrors: %v", release, err)
		return fmt.Errorf("failed to make request for %v mirrors: %v", release, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// break
	default:
		c.logger.Error().Msgf("failed to get amazon mirrors. got unexpected HTTP response: %d (%s)", resp.StatusCode, resp.Status)
		return fmt.Errorf("failed to make request for %v mirrors: %v", release, err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.logger.Error().Msgf("failed to read http body: %v", err)
		return fmt.Errorf("failed to read http body: %v", err)
	}

	urls := strings.Split(string(body), "\n")
	urls = urls[:len(urls)-1]

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
