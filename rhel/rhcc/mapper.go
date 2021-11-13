package rhcc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quay/zlog"
	"golang.org/x/time/rate"
)

// MappingFile is a struct for mapping file between container NAME label and
// container registry repository location.
type mappingFile struct {
	Data map[string][]string `json:"data"`
}

func (m *mappingFile) Get(ctx context.Context, _ *http.Client, name string) []string {
	if repos, ok := m.Data[name]; ok {
		zlog.Debug(ctx).Str("name", name).
			Msg("name present in mapping file")
		return repos
	}
	return []string{}
}

// UpdatingMapper provides local container name -> repos mapping via a
// continually updated local mapping file.
type updatingMapper struct {
	URL string
	// an atomic value holding the latest
	// parsed MappingFile
	mapping atomic.Value

	// Machinery for updating the mapping file.
	reqRate      *rate.Limiter
	mu           sync.Mutex // protects lastModified
	lastModified string
}

// NewUpdatingMapper returns an UpdatingMapper.
//
// The update period is unconfigurable. The first caller after the period loses
// and must update the mapping file.
func newUpdatingMapper(url string, init *mappingFile) *updatingMapper {
	lu := &updatingMapper{
		URL:     url,
		reqRate: rate.NewLimiter(rate.Every(10*time.Minute), 1),
	}
	lu.mapping.Store(init)
	// If we were provided an initial mapping, pull the first token.
	if init != nil {
		lu.reqRate.Allow()
	}
	return lu
}

// Get translates container names to repos using a mapping file.
//
// Get is safe for concurrent usage.
func (u *updatingMapper) Get(ctx context.Context, c *http.Client, name string) []string {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/name2repos/UpdatingMapper.Get")
	if name == "" {
		return []string{}
	}
	if u.reqRate.Allow() {
		zlog.Debug(ctx).Msg("got unlucky, updating mapping file")
		if err := u.do(ctx, c); err != nil {
			zlog.Error(ctx).
				Err(err).
				Msg("error updating mapping file")
		}
	}

	// interface conversion guaranteed to pass, see
	// constructor.
	m := u.mapping.Load().(*mappingFile)
	if m == nil {
		return []string{}
	}
	return m.Get(ctx, nil, name)
}

func (u *updatingMapper) Fetch(ctx context.Context, c *http.Client) error {
	return u.do(ctx, c)
}

// Do is an internal method called to perform an atomic update of the mapping
// file.
//
// This method may be ran concurrently.
func (u *updatingMapper) do(ctx context.Context, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx, "component", "rhel/rhcc/UpdatingMapper.do", "url", u.URL)
	zlog.Debug(ctx).Msg("attempting fetch of name2repos mapping file")

	u.mu.Lock()
	defer u.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return err
	}
	if u.lastModified != "" {
		req.Header.Set("if-modified-since", u.lastModified)
	}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		zlog.Debug(ctx).
			Str("since", u.lastModified).
			Msg("response not modified; no update necessary")
		return nil
	default:
		return fmt.Errorf("received status code %q querying mapping url", resp.StatusCode)
	}

	var mapping mappingFile
	err = json.NewDecoder(resp.Body).Decode(&mapping)
	if err != nil {
		return fmt.Errorf("failed to decode mapping file: %w", err)
	}
	u.lastModified = resp.Header.Get("last-modified")
	// atomic store of mapping file
	u.mapping.Store(&mapping)
	zlog.Debug(ctx).Msg("atomic update of local mapping file complete")
	return nil
}
