package aws

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/quay/claircore/aws/internal/alas"
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
	log     *slog.Logger
	mirrors []*url.URL
}

func NewClient(ctx context.Context, hc *http.Client, release Release) (*Client, error) {
	if hc == nil {
		return nil, errors.New("http.Client not provided")
	}
	client := &Client{
		c:       hc,
		log:     slog.With("release", string(release)),
		mirrors: []*url.URL{},
	}
	tctx, cancel := context.WithTimeout(ctx, defaultOpTimeout)
	defer cancel()
	err := client.getMirrors(tctx, release.mirrorlist())
	return client, err
}

// RepoMD returns a alas.RepoMD containing sha256 information of a repositories contents
func (c *Client) RepoMD(ctx context.Context) (alas.RepoMD, error) {
	log := c.log
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, repoDataPath)
		log := log.With("mirror", m.String())

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			log.ErrorContext(ctx, "failed to make request object", "reason", err)
			continue
		}

		log.DebugContext(ctx, "attempting repomd download")
		resp, err := c.c.Do(req)
		if err != nil {
			log.ErrorContext(ctx, "failed to retrieve repomd", "reason", err)
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			log.ErrorContext(ctx, "unexpected HTTP response",
				"code", resp.StatusCode,
				"status", resp.Status)
			continue
		}

		repoMD := alas.RepoMD{}
		dec := xml.NewDecoder(resp.Body)
		dec.CharsetReader = xmlutil.CharsetReader
		if err := dec.Decode(&repoMD); err != nil {
			log.ErrorContext(ctx, "failed xml unmarshal", "reason", err)
			continue
		}

		log.DebugContext(ctx, "success")
		return repoMD, nil
	}

	log.ErrorContext(ctx, "exhausted all mirrors")
	return alas.RepoMD{}, fmt.Errorf("all mirrors failed to retrieve repo metadata")
}

// Updates returns the *http.Response of the first mirror to establish a connection
func (c *Client) Updates(ctx context.Context) (io.ReadCloser, error) {
	log := c.log
	for _, mirror := range c.mirrors {
		m := *mirror
		m.Path = path.Join(m.Path, updatesPath)
		log := log.With("mirror", m.String())

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.String(), nil)
		if err != nil {
			log.ErrorContext(ctx, "failed to make request object", "reason", err)
			continue
		}

		tf, err := tmp.NewFile("", "")
		if err != nil {
			log.ErrorContext(ctx, "failed to open temp file", "reason", err)
			continue
		}
		var success bool
		defer func() {
			if !success {
				if err := tf.Close(); err != nil {
					log.WarnContext(ctx, "unable to close spool", "reason", err)
				}
			}
		}()

		resp, err := c.c.Do(req)
		if err != nil {
			log.ErrorContext(ctx, "failed to retrieve updates", "reason", err)
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// break
		default:
			log.ErrorContext(ctx, "unexpected HTTP response",
				"code", resp.StatusCode,
				"status", resp.Status)
			continue
		}

		if _, err := io.Copy(tf, resp.Body); err != nil {
			return nil, err
		}
		if o, err := tf.Seek(0, io.SeekStart); err != nil || o != 0 {
			return nil, err
		}
		gz, err := gzip.NewReader(tf)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}

		log.DebugContext(ctx, "success")
		success = true
		return &gzippedFile{
			Reader: gz,
			Closer: tf,
		}, nil
	}

	log.ErrorContext(ctx, "exhausted all mirrors")
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
	log := c.log

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read http body: %v", err)
	}

	b := strings.TrimSuffix(string(body), "\n")
	urls := strings.SplitSeq(b, "\n")

	for u := range urls {
		uu, err := url.Parse(u)
		if err != nil {
			return fmt.Errorf("could not parse returned mirror %v as URL: %v", u, err)
		}
		c.mirrors = append(c.mirrors, uu)
	}

	log.DebugContext(ctx, "successfully got list of mirrors")
	return nil
}
