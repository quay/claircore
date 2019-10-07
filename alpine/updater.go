package alpine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	dbURL = "https://raw.githubusercontent.com/alpinelinux/alpine-secdb/master/%s/%s.yaml"
)

// DBUrl will return a fqdn'd url for a given release,repo pair
func DBUrl(release Release, repo Repo) string {
	return fmt.Sprintf(dbURL, release, repo)
}

type Updater struct {
	client  *http.Client
	release Release
	repo    Repo
	url     string
	logger  *zerolog.Logger // hack until the context-ified interfaces are used
}

var _ driver.Updater = (*Updater)(nil)
var _ driver.FetcherNG = (*Updater)(nil)

// Option configures the provided Updater
type Option func(*Updater) error

// NewUpdater returns an updater configured according to the provided Options.
func NewUpdater(release Release, repo Repo, opts ...Option) (*Updater, error) {
	u := &Updater{
		client:  http.DefaultClient,
		release: release,
		repo:    repo,
		url:     DBUrl(release, repo),
	}

	for _, o := range opts {
		if err := o(u); err != nil {
			return nil, err
		}
	}

	if u.logger == nil {
		u.logger = &log.Logger
	}

	return u, nil
}

func (u *Updater) Name() string {
	return fmt.Sprintf("alpine-%s-%s-updater", u.repo, u.release)
}

func (u *Updater) Fetch() (io.ReadCloser, string, error) {
	ctx := u.logger.WithContext(context.Background())
	ctx, done := context.WithTimeout(ctx, time.Minute)
	defer done()
	r, hint, err := u.FetchContext(ctx, "")
	return r, string(hint), err
}

func (u *Updater) FetchContext(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().Str("component", u.Name()).Logger()

	log.Info().Str("database", u.url).Msg("starting fetch")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to construct request: %w", err)
	}

	if hint != "" {
		log.Debug().Msgf("using hint %q", hint)
		req.Header.Set("If-Modified-Since", string(hint))
	}

	res, err := u.client.Do(req)
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: error making request: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		//break
	case http.StatusNotModified:
		log.Info().Msg("database unchanged since last fetch")
		return nil, hint, driver.Unchanged
	default:
		return nil, hint, fmt.Errorf("alpine: http response error: %s %d", res.Status, res.StatusCode)
	}
	log.Debug().Msg("successfully requested database")

	tf, err := tmp.NewFile("", u.Name()+".")
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to open tempfile: %w", err)
	}
	log.Debug().Msgf("created tempfile %q", tf.Name())

	var r io.Reader = res.Body
	if _, err := io.Copy(tf, r); err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to copy resp body to tempfile: %w", err)
	}
	if n, err := tf.Seek(0, io.SeekStart); err != nil || n != 0 {
		return nil, hint, fmt.Errorf("alpine: unable to seek database to start: at %d, %v", n, err)
	}
	log.Debug().Msg("decompressed and buffered database")

	if h := res.Header.Get("Last-Modified"); h != "" {
		hint = driver.Fingerprint(h)
	} else {
		hint = driver.Fingerprint(res.Header.Get("Date"))
	}
	log.Debug().Msgf("using new hint %q", hint)

	return tf, hint, nil
}
