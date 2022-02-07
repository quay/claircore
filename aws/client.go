package aws

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/quay/alas"
	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/xmlutil"
	"github.com/quay/claircore/pkg/tmp"
)

const (
	repoDataPath     = "/repodata/repomd.xml"
	updatesPath      = "/repodata/updateinfo.xml.gz"
	defaultOpTimeout = 15 * time.Second
)

// Client is an http for accessing ALAS mirrors.
type Client struct {
	c       *http.Client
	mirrors []*url.URL
}

func NewClient(ctx context.Context, hc *http.Client, release Release) (*Client, error) {
	ctx = zlog.ContextWithValues(ctx, "release", string(release))
	if hc == nil {
		return nil, errors.New("http.Client not provided")
	}
	client := &Client{
		c:       hc,
		mirrors: []*url.URL{},
	}
	tctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	err := client.getMirrors(tctx, release.mirrorlist())
	return client, err
}

// RepoMD returns a alas.RepoMD containing sha256 information of a repositories contents
func (c *Client) RepoMD(ctx context.Context) (alas.RepoMD, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "aws/Client.RepoMD")
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, repoDataPath)
		ctx := zlog.ContextWithValues(ctx, "mirror", m.String())

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed to make request object")
			continue
		}

		zlog.Debug(ctx).Msg("attempting repomd download")
		resp, err := c.c.Do(req)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed to retrieve repomd")
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			zlog.Error(ctx).
				Int("code", resp.StatusCode).
				Str("status", resp.Status).
				Msg("unexpected HTTP response")
			continue
		}

		repoMD := alas.RepoMD{}
		dec := xml.NewDecoder(resp.Body)
		dec.CharsetReader = xmlutil.CharsetReader
		if err := dec.Decode(&repoMD); err != nil {
			zlog.Error(ctx).
				Err(err).
				Msg("failed xml unmarshal")
			continue
		}

		zlog.Debug(ctx).Msg("success")
		return repoMD, nil
	}

	zlog.Error(ctx).Msg("exhausted all mirrors")
	return alas.RepoMD{}, fmt.Errorf("all mirrors failed to retrieve repo metadata")
}

// Updates returns the *http.Response of the first mirror to establish a connection
func (c *Client) Updates(ctx context.Context) (io.ReadCloser, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "aws/Client.Updates")
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, updatesPath)
		ctx := zlog.ContextWithValues(ctx, "mirror", m.String())

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed to make request object")
			continue
		}

		tf, err := tmp.NewFile("", "")
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed to open temp file")
			continue
		}

		resp, err := c.c.Do(req)
		if err != nil {
			zlog.Error(ctx).Err(err).Msg("failed to retrieve updates")
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			zlog.Error(ctx).
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
		gz, err := gzip.NewReader(tf)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}

		zlog.Debug(ctx).Msg("success")
		return &gzippedFile{
			Reader: gz,
			Closer: tf,
		}, nil
	}

	zlog.Error(ctx).Msg("exhausted all mirrors")
	return nil, fmt.Errorf("all update_info mirrors failed to return a response")
}

// gzippedFile implements io.ReadCloser by proxying calls to different
// underlying implementations. This is used to make sure the file that backs the
// downloaded security database has Close called on it.
type gzippedFile struct {
	io.Reader
	io.Closer
}

func (c *Client) getMirrors(ctx context.Context, list string) error {
	ctx = zlog.ContextWithValues(ctx, "component", "aws/Client.getMirrors")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, list, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for mirror list: %v", err)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request for mirrors: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// break
	default:
		return fmt.Errorf("failed to make request for mirrors: unexpected response %d %s", resp.StatusCode, resp.Status)
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

	zlog.Debug(ctx).
		Msg("successfully got list of mirrors")
	return nil
}
