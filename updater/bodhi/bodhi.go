// Package bodhi is update machinery that pulls security updates from a Bodhi
// instance.
//
// The Fedora Project uses a Bodhi server to track updates, hosted at
// https://bodhi.fedoraproject.org. This package uses the server REST API
// documented at https://bodhi.fedoraproject.org/docs/server_api/.
package bodhi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/quay/zlog"
)

var defaultAPI *url.URL

func init() {
	var err error
	defaultAPI, err = url.Parse("https://bodhi.fedoraproject.org/")
	if err != nil {
		panic(err)
	}
}

// Client is a Bodhi client.
//
// See the documentation at:
// https://bodhi.fedoraproject.org/docs/server_api/
type client struct {
	Root   *url.URL
	Client *http.Client
}

func unexpectedResponse(res *http.Response) error {
	return fmt.Errorf("bodhi: unexpected status for %q: %v", res.Request.URL, res.Status)
}

func (f *client) GetReleases(ctx context.Context) ([]release, error) {
	u, err := f.Root.Parse("releases")
	if err != nil {
		return nil, err
	}
	u.RawQuery = (url.Values{"rows_per_page": {"100"}}).Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")

	res, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, unexpectedResponse(res)
	}

	var rr releases
	if err := json.NewDecoder(res.Body).Decode(&rr); err != nil {
		return nil, err
	}
	return rr.Releases, nil
}

type releases struct {
	pagination
	Releases []release `json:"releases"`
}

type pagination struct {
	Page  int `json:"page"`
	Pages int `json:"pages"`
	Total int `json:"total"`
}
type release struct {
	Name     string `json:"name"`
	LongName string `json:"long_name"`
	Version  string `json:"version"`
	State    string `json:"state"`
}

func (r release) Archived() bool {
	return r.State == "archived"
}
func (r release) Pending() bool {
	return r.State == "pending"
}
func (r release) Current() bool {
	return r.State == "current"
}
func (r release) String() string {
	return r.Name
}

func (c *client) AnySince(ctx context.Context, rls *release, t time.Time) (bool, error) {
	u, err := c.Root.Parse("updates")
	if err != nil {
		return false, err
	}
	u.RawQuery = (url.Values{
		"status":        {"stable"},
		"type":          {"security"},
		"rows_per_page": {"1"},
		"release":       {rls.Name},
		"pushed_since":  {t.Format(time.RFC3339)},
	}).Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}

	res, err := c.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, unexpectedResponse(res)
	}

	var upd updates
	if err := json.NewDecoder(res.Body).Decode(&upd); err != nil {
		return false, err
	}
	return len(upd.Updates) != 0, nil
}

// Fetch returns all updates marked "stable" and "security" and serializes them
// into JSON using the supplied Writer.
func (c *client) Fetch(ctx context.Context, rls *release, to io.Writer) error {
	// pagination state
	var pg updates
	var total int
	var retry bool
	// setup
	u, err := c.Root.Parse("updates")
	if err != nil {
		return err
	}
	v := url.Values{
		"status":        {"stable"},
		"type":          {"security"},
		"rows_per_page": {"100"},
		"release":       {rls.Name},
	}
	enc := json.NewEncoder(to)

	// This could be done quicker in parallel, but remember that updaters are
	// run in parallel, also.
	for i := 0; pg.more(); i++ {
		v.Set("page", strconv.Itoa(pg.Page+1))
		u.RawQuery = v.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		res, err := c.Client.Do(req)
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return unexpectedResponse(res)
		}
		err = json.NewDecoder(res.Body).Decode(&pg)
		res.Body.Close()
		if err != nil {
			return err
		}
		if i == 0 { // initial set up
			total = pg.Total
		}
		if total != pg.Total {
			if retry {
				retry = false
				zlog.Info(ctx).
					Msg("updates pushed while paginating updates, retrying")
				pg = updates{}
				i = -1
				continue
			}
			return errors.New("bodhi: updates pushed while paginating updates")
		}

		for i := range pg.Updates {
			if err := enc.Encode(&pg.Updates[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

type updates struct {
	pagination
	Updates []update `json:"updates"`
}

func (u *updates) more() bool {
	return u.Page == 0 ||
		u.Page < u.Pages
}

type update struct {
	ID       string  `json:"updateid"`
	Title    string  `json:"title"`
	Hash     string  `json:"version_hash"`
	URL      string  `json:"url"`
	Severity string  `json:"severity"`
	Builds   []build `json:"builds"`
	Release  release `json:"release"`
}

type build struct {
	NVR       string `json:"nvr"`
	Signed    bool   `json:"signed"`
	ReleaseID int    `json:"release_id"`
	Kind      string `json:"type"`
	Epoch     int    `json:"epoch"`
}
