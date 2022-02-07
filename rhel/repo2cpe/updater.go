package repo2cpe

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

// Interval is how often we attempt to update the mapping file.
var interval = rate.Every(10 * time.Minute)

// UpdatingMapper provides local repo -> cpe mapping
// via a continually updated local mapping file
type UpdatingMapper struct {
	URL    string
	Client *http.Client
	// an atomic value holding the latest
	// parsed MappingFile
	mapping atomic.Value

	// Machinery for updating the mapping file.
	reqRate      *rate.Limiter
	mu           sync.Mutex // protects lastModified
	lastModified string
}

// NewUpdatingMapper returns an UpdatingMapper.
func NewUpdatingMapper(client *http.Client, url string, init *MappingFile) *UpdatingMapper {
	if client == nil {
		panic("nil *http.Client passed")
	}
	lu := &UpdatingMapper{
		URL:     url,
		Client:  client,
		reqRate: rate.NewLimiter(interval, 1),
	}
	lu.mapping.Store(init)
	// If we were provided an initial mapping, pull the first token.
	if init != nil {
		lu.reqRate.Allow()
	}
	return lu
}

// Get translates repositories into CPEs using a mapping file.
//
// Get is safe for concurrent usage.
func (u *UpdatingMapper) Get(ctx context.Context, rs []string) ([]string, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/repo2cpe/UpdatingMapper.Get")
	if len(rs) == 0 {
		return []string{}, nil
	}
	if u.reqRate.Allow() {
		zlog.Debug(ctx).Msg("got unlucky, updating mapping file")
		if err := u.do(ctx); err != nil {
			zlog.Error(ctx).
				Err(err).
				Msg("error updating mapping file")
		}
	}

	// interface conversion guaranteed to pass, see
	// constructor.
	m := u.mapping.Load().(*MappingFile)
	if m == nil {
		return []string{}, nil
	}
	return m.Get(ctx, rs)
}

func (u *UpdatingMapper) Fetch(ctx context.Context) error {
	return u.do(ctx)
}

// do is an internal method called to perform an atomic update
// of the mapping file.
//
// this method may be ran concurrently.
func (u *UpdatingMapper) do(ctx context.Context) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/repo2cpe/UpdatingMapper.do",
		"url", u.URL)
	zlog.Debug(ctx).Msg("attempting fetch of repo2cpe mapping file")

	u.mu.Lock()
	defer u.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return err
	}
	if u.lastModified != "" {
		req.Header.Set("if-modified-since", u.lastModified)
	}

	resp, err := u.Client.Do(req)
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

	var mapping MappingFile
	err = json.NewDecoder(resp.Body).Decode(&mapping)
	if err != nil {
		return fmt.Errorf("failed to decode mapping file: %v", err)
	}

	u.lastModified = resp.Header.Get("last-modified")
	// atomic store of mapping file
	u.mapping.Store(&mapping)
	zlog.Debug(ctx).Msg("atomic update of local mapping file complete")
	return nil
}
