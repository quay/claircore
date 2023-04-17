package debian

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
)

var sourceRepos = [3]string{"main", "contrib", "non-free"}

// NewSourcesMap returns a SourcesMap but does not perform any
// inserts into the map. That needs to be done explicitly by calling
// the Update method.
func newSourcesMap(client *http.Client, srcs []sourceURL) *sourcesMap {
	return &sourcesMap{
		urls:      srcs,
		sourceMap: make(map[string]map[string]map[string]struct{}),
		etagMap:   make(map[string]string),
		client:    client,
	}
}

type sourceURL struct {
	distro string
	url    *url.URL
}

// sourcesMap wraps a map that defines the relationship between a source
// package and its associated binaries. It offers an Update method
// to populate and update the map. It is Release-centric.
//
// It should have the same lifespan as the Updater to save allocations
// and take advantage of the entity tag that Debian sends back.
type sourcesMap struct {
	urls       []sourceURL
	mu, etagMu sync.RWMutex
	// sourceMap maps distribution -> source package -> binary packages
	sourceMap map[string]map[string]map[string]struct{}
	etagMap   map[string]string
	client    *http.Client
}

// Get returns all the binaries associated with a source package
// identified by a string. Empty slice is returned if the source
// doesn't exist in the map.
func (m *sourcesMap) Get(distro, source string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bins := []string{}
	for bin := range m.sourceMap[distro][source] {
		bins = append(bins, bin)
	}
	return bins
}

// Update pulls the Sources.gz files for the different repos and saves
// the resulting source to binary relationships.
func (m *sourcesMap) Update(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, source := range m.urls {
		// Required as source is overwritten upon each iteration,
		// which may cause a race condition when used below in g.Go.
		src := source
		for _, r := range sourceRepos {
			u, err := source.url.Parse(path.Join(r, `source`, `Sources.gz`))
			g.Go(func() error {
				if err != nil {
					return fmt.Errorf("unable to construct URL: %w", err)
				}
				if err := m.fetchSources(ctx, src.distro, u.String()); err != nil {
					return fmt.Errorf("unable to fetch sources: %w", err)
				}
				return nil
			})
		}
	}
	return g.Wait()
}

func (m *sourcesMap) fetchSources(ctx context.Context, distro, url string) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "debian/sourcemapper.fetchSources",
		"url", url)
	zlog.Debug(ctx).Msg("attempting fetch of Sources file")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	m.etagMu.RLock()
	etag := m.etagMap[url]
	m.etagMu.RUnlock()
	req.Header.Set("If-None-Match", etag)

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		if etag == "" || etag != resp.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		zlog.Debug(ctx).Msg("already processed the latest version of the file")
		return nil
	default:
		return fmt.Errorf("received status code %d querying mapping url %s", resp.StatusCode, url)
	}
	m.etagMu.Lock()
	m.etagMap[url] = resp.Header.Get("etag")
	m.etagMu.Unlock()

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Type") {
	case "application/gzip", "application/x-gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer reader.Close()
	default:
		return fmt.Errorf("received bad content-type %s querying mapping url %s", resp.Header.Get("Content-Type"), url)
	}

	tp := textproto.NewReader(bufio.NewReader(reader))
	hdr, err := tp.ReadMIMEHeader()
	for ; err == nil && len(hdr) > 0; hdr, err = tp.ReadMIMEHeader() {
		source := hdr.Get("Package")
		if source == "linux" {
			continue
		}
		binaries := hdr.Get("Binary")
		m.mu.Lock()
		if m.sourceMap[distro] == nil {
			m.sourceMap[distro] = make(map[string]map[string]struct{})
		}
		if m.sourceMap[distro][source] == nil {
			m.sourceMap[distro][source] = make(map[string]struct{})
		}
		for _, bin := range strings.Split(binaries, ", ") {
			m.sourceMap[distro][source][bin] = struct{}{}
		}
		m.mu.Unlock()
	}
	switch {
	case errors.Is(err, io.EOF):
	default:
		return fmt.Errorf("could not read Sources file %s: %w", url, err)
	}

	return nil
}
