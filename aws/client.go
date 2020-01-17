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

// Client is an http for accessing ALAS mirrors.
type Client struct {
	c       *http.Client
	mirrors []*url.URL
}

func NewClient(ctx context.Context, release Release) (*Client, error) {
	client := &Client{
		c:       &http.Client{},
		mirrors: []*url.URL{},
	}
	tctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	err := client.getMirrors(tctx, release)
	return client, err
}

// RepoMD returns a alas.RepoMD containing sha256 information of a repositories contents
func (c *Client) RepoMD(ctx context.Context) (alas.RepoMD, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "aws/Client.RepoMD").
		Logger()
	ctx = log.WithContext(ctx)
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, repoDataPath)
		log := log.With().Str("mirror", m.String()).Logger()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			log.Error().Err(err).Msg("failed to make request object")
			continue
		}

		log.Debug().Msg("attempting repomd download")
		resp, err := c.c.Do(req)
		if err != nil {
			log.Error().Err(err).Msg("failed to retrieve repomd")
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			log.Error().
				Int("code", resp.StatusCode).
				Str("status", resp.Status).
				Msg("unexpected HTTP response")
			continue
		}

		repoMD := alas.RepoMD{}
		err = xml.NewDecoder(resp.Body).Decode(&repoMD)
		if err != nil {
			log.Error().
				Err(err).
				Msg("failed xml unmarshal")
			continue
		}

		log.Debug().Msg("success")
		return repoMD, nil
	}

	log.Error().Msg("exhausted all mirrors")
	return alas.RepoMD{}, fmt.Errorf("all mirrors failed to retrieve repo metadata")
}

// Updates returns the *http.Response of the first mirror to establish a connection
func (c *Client) Updates(ctx context.Context) (io.ReadCloser, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "aws/Client.Updates").
		Logger()
	ctx = log.WithContext(ctx)
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, updatesPath)
		log := log.With().Str("mirror", m.String()).Logger()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			log.Error().Err(err).Msg("failed to make request object")
			continue
		}

		tf, err := tmp.NewFile("", "")
		if err != nil {
			log.Error().Err(err).Msg("failed to open temp file")
			continue
		}

		resp, err := c.c.Do(req)
		if err != nil {
			log.Error().Err(err).Msg("failed to retrieve updates")
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			log.Error().
				Int("code", resp.StatusCode).
				Str("status", resp.Status).
				Msg("unexpected HTTP response")
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

		log.Debug().Msg("success")
		return tf, nil
	}

	log.Error().Msg("exhausted all mirrors")
	return nil, fmt.Errorf("all update_info mirrors failed to return a response")
}

func (c *Client) getMirrors(ctx context.Context, release Release) error {
	var (
		req *http.Request
		err error
	)
	log := zerolog.Ctx(ctx).With().
		Str("component", "aws/Client.getMirrors").
		Str("release", string(release)).
		Logger()
	ctx = log.WithContext(ctx)

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
		return fmt.Errorf("failed to make request for %v mirrors: %v", release, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// break
	default:
		return fmt.Errorf("failed to make request for %v mirrors: unexpected response %d %s", release, resp.StatusCode, resp.Status)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read http body: %v", err)
	}

	urls := strings.Split(string(body), "\n")
	urls = urls[:len(urls)-1]

	for _, u := range urls {
		uu, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("could not parse returned mirror %v as URL: %v", u, err)
		}
		c.mirrors = append(c.mirrors, uu)
	}

	log.Debug().
		Str("mirrors", fmt.Sprint(c.mirrors)).
		Msg("successfully got list of mirrors")
	return nil
}
