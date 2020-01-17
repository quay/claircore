package alpine

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

func (u *Updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "alpine/Updater.Fetch").
		Logger()
	ctx = log.WithContext(ctx)

	log.Info().Str("database", u.url).Msg("starting fetch")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to construct request: %w", err)
	}

	if hint != "" {
		log.Debug().
			Str("hint", string(hint)).
			Msg("using hint")
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
	log.Debug().
		Str("name", tf.Name()).
		Msg("created tempfile")

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
	log.Debug().
		Str("hint", string(hint)).
		Msg("using new hint")

	return tf, hint, nil
}
