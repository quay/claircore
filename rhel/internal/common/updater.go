package common

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quay/zlog"
	"golang.org/x/time/rate"
)

// Interval is how often we attempt to update the mapping file.
var interval = rate.Every(24 * time.Hour)

// Updater returns a value that's periodically updated.
type Updater struct {
	url          string
	typ          reflect.Type
	value        atomic.Value
	reqRate      *rate.Limiter
	mu           sync.RWMutex // protects lastModified
	lastModified string
}

// NewUpdater returns an Updater holding a value of the type passed as "init",
// periodically updated from the endpoint "url."
//
// To omit an initial value, use a typed nil pointer.
func NewUpdater(url string, init interface{}) *Updater {
	u := Updater{
		url:     url,
		typ:     reflect.TypeOf(init).Elem(),
		reqRate: rate.NewLimiter(interval, 1),
	}
	u.value.Store(init)
	// If we were provided an initial value, pull the first token.
	if !reflect.ValueOf(init).IsNil() {
		u.reqRate.Allow()
	}
	return &u
}

// Get returns a pointer to the current copy of the value. The Get call may be
// hijacked to update the value from the configured endpoint.
func (u *Updater) Get(ctx context.Context, c *http.Client) (interface{}, error) {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/internal/common/Updater.Get")
	var err error
	if u.url != "" && u.reqRate.Allow() {
		zlog.Debug(ctx).Msg("got unlucky, updating mapping file")
		err = u.Fetch(ctx, c)
		if err != nil {
			zlog.Error(ctx).
				Err(err).
				Msg("error updating mapping file")
		}
	}

	return u.value.Load(), err
}

// Fetch attempts to perform an atomic update of the mapping file.
//
// Fetch is safe to call concurrently.
func (u *Updater) Fetch(ctx context.Context, c *http.Client) error {
	ctx = zlog.ContextWithValues(ctx,
		"component", "rhel/internal/common/Updater.Fetch",
		"url", u.url)
	zlog.Debug(ctx).Msg("attempting fetch of mapping file")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return err
	}
	u.mu.RLock()
	if u.lastModified != "" {
		req.Header.Set("if-modified-since", u.lastModified)
	}
	u.mu.RUnlock()

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
		return fmt.Errorf("received status code %d querying mapping url", resp.StatusCode)
	}

	v := reflect.New(u.typ).Interface()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode mapping file: %w", err)
	}

	u.mu.Lock()
	u.lastModified = resp.Header.Get("last-modified")
	u.mu.Unlock()
	// atomic store of mapping file
	u.value.Store(v)
	zlog.Debug(ctx).Msg("atomic update of local mapping file complete")
	return nil
}
