package oracle

import (
	"compress/bzip2"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/quay/claircore/libvuln/driver"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const dbURL = `https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2`

// Updater implements driver.Updater for Oracle Linux.
type Updater struct {
	client *http.Client
	url    string
	bzip   bool

	logger *zerolog.Logger // hack until the context-ified interfaces are used
}

// Option configures the provided Updater.
type Option func(*Updater) error

// NewUpdater returns an updater configured according to the provided Options.
func NewUpdater(opts ...Option) (*Updater, error) {
	u := Updater{
		client: http.DefaultClient,
		url:    dbURL,
		bzip:   true,
	}
	for _, o := range opts {
		if err := o(&u); err != nil {
			return nil, err
		}
	}
	if u.logger == nil {
		u.logger = &log.Logger
	}

	return &u, nil
}

// WithClient returns an Option that will make the Updater use the specified
// http.Client, instead of http.DefaultClient.
func WithClient(c *http.Client) Option {
	return func(u *Updater) error {
		u.client = c
		return nil
	}
}

// WithURL overrides the default URL to fetch an OVAL database.
func WithURL(url string) Option {
	return func(u *Updater) error {
		u.bzip = false
		u.url = url
		return nil
	}
}

// WithLogger sets the default logger.
//
// Functions that take a context.Context will use the logger embedded in there
// instead of the Logger passed in via this Option.
func WithLogger(l *zerolog.Logger) Option {
	return func(u *Updater) error {
		u.logger = l
		return nil
	}
}

var _ driver.Updater = (*Updater)(nil)
var _ driver.FetcherNG = (*Updater)(nil)

// Name satifies the driver.Updater interface.
func (u *Updater) Name() string {
	return "oracle-updater"
}

type tempfile struct {
	*os.File
}

func (t *tempfile) Close() error {
	if err := t.File.Close(); err != nil {
		return err
	}
	return os.Remove(t.File.Name())
}

// Fetch satifies the driver.Updater interface.
func (u *Updater) Fetch() (io.ReadCloser, string, error) {
	ctx := u.logger.WithContext(context.Background())
	ctx, done := context.WithTimeout(ctx, time.Minute)
	defer done()
	r, hint, err := u.FetchContext(ctx, "")
	return r, string(hint), err
}

// FetchContext is like Fetch, but with Context.
//
// FetchContext satisfies the driver.FetcherNG interface.
func (u *Updater) FetchContext(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().Str("component", u.Name()).Logger()

	log.Info().Str("database", u.url).Msg("starting fetch")
	req, err := http.NewRequestWithContext(ctx, "GET", u.url, nil)
	if err != nil {
		return nil, hint, fmt.Errorf("oracle: unable to construct request: %w", err)
	}
	if hint != "" {
		log.Debug().Msgf("using hint %q", hint)
		req.Header.Set("If-Modified-Since", string(hint))
	}
	res, err := u.client.Do(req)
	if err != nil {
		return nil, hint, fmt.Errorf("oracle: error making request: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		log.Info().Msg("unchanged")
		return nil, hint, driver.Unchanged
	default:
		return nil, hint, fmt.Errorf("oracle: error making request: %w", err)
	}
	log.Debug().Msg("request ok")

	f, err := ioutil.TempFile("", u.Name()+".")
	if err != nil {
		return nil, hint, fmt.Errorf("oracle: unable to open tempfile: %w", err)
	}
	log.Debug().Msgf("creating tempfile %q", f.Name())

	var r io.Reader = res.Body
	if u.bzip {
		r = bzip2.NewReader(res.Body)
	}
	if _, err := io.Copy(f, r); err != nil {
		return nil, hint, fmt.Errorf("oracle: unable to open tempfile: %w", err)
	}
	if n, err := f.Seek(0, io.SeekStart); err != nil || n != 0 {
		return nil, hint, fmt.Errorf("oracle: unable to seek database to start: at %d, %v", n, err)
	}
	log.Debug().Msg("decompressed and buffered database")

	if h := res.Header.Get("Last-Modified"); h != "" {
		hint = driver.Fingerprint(h)
	} else {
		hint = driver.Fingerprint(res.Header.Get("Date"))
	}
	log.Debug().Msgf("using new hint %q", hint)

	return &tempfile{f}, hint, nil
}
