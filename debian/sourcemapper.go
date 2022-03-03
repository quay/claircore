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
	"strings"
	"sync"

	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"
)

const sourcesURL = "https://ftp.debian.org/debian/dists/%s/%s/source/Sources.gz"

var sourceRepos = [3]string{"main", "contrib", "non-free"}

// NewSourcesMap returns a SourcesMap but does not perform any
// inserts into the map. That needs to be done explitly by calling
// the Update method.
func NewSourcesMap(release Release, client *http.Client) *SourcesMap {
	return &SourcesMap{
		release:    release,
		sourcesURL: sourcesURL,
		sourceMap:  make(map[string]map[string]struct{}),
		mu:         &sync.RWMutex{},
		etagMap:    make(map[string]string),
		etagMu:     &sync.RWMutex{},
		client:     client,
	}
}

// SourcesMap wraps a map that defines the relationship between a source
// package and it's associated binaries. It offers an Update method
// to populate and update the map. It is Release-centric.
//
// It should have the same lifespan as the Updater to save allocations
// and take advantage of the entity tag that debian sends back.
type SourcesMap struct {
	release    Release
	sourcesURL string
	mu, etagMu *sync.RWMutex
	sourceMap  map[string]map[string]struct{}
	etagMap    map[string]string
	client     *http.Client
}

// Get returns all the binaries associated with a source package
// identified by a string. Empty slice is returned if the source
// doesn't exist in the map.
func (m *SourcesMap) Get(source string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	bins := []string{}
	if m.sourceMap[source] == nil {
		return bins
	}

	for bin := range m.sourceMap[source] {
		bins = append(bins, bin)
	}
	return bins
}

// Update pulls the Sources.gz files for the different repos and saves
// the resulting source to binary relationships.
func (m *SourcesMap) Update(ctx context.Context) error {
	if m.release == Wheezy {
		// There are no Wheezy records we assume the source->binary relationship of Jessie.
		m.release = Jessie
	}
	g, ctx := errgroup.WithContext(ctx)
	for _, r := range sourceRepos {
		url := fmt.Sprintf(m.sourcesURL, m.release, r)
		g.Go(func() error {
			err := m.fetchSources(ctx, url)
			if err != nil {
				return fmt.Errorf("unable to fetch sources: %w", err)
			}
			return nil
		})
	}
	return g.Wait()
}

func (m *SourcesMap) fetchSources(ctx context.Context, url string) error {
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
		if m.sourceMap[source] == nil {
			m.sourceMap[source] = make(map[string]struct{})
		}
		for _, bin := range strings.Split(binaries, ", ") {
			m.sourceMap[source][bin] = struct{}{}
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
