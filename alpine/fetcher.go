package alpine

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/quay/zlog"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

func (u *updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "alpine/Updater.Fetch")

	zlog.Info(ctx).Str("database", u.url).Msg("starting fetch")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to construct request: %w", err)
	}

	if hint != "" {
		zlog.Debug(ctx).
			Str("hint", string(hint)).
			Msg("using hint")
		req.Header.Set("if-none-match", string(hint))
	}

	res, err := u.client.Do(req)
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: error making request: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		if t := string(hint); t == "" || t != res.Header.Get("etag") {
			break
		}
		fallthrough
	case http.StatusNotModified:
		zlog.Info(ctx).Msg("database unchanged since last fetch")
		return nil, hint, driver.Unchanged
	default:
		return nil, hint, fmt.Errorf("alpine: http response error: %s %d", res.Status, res.StatusCode)
	}
	zlog.Debug(ctx).Msg("successfully requested database")

	tf, err := tmp.NewFile("", u.Name()+".")
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to open tempfile: %w", err)
	}
	zlog.Debug(ctx).
		Str("name", tf.Name()).
		Msg("created tempfile")

	var r io.Reader = res.Body
	if _, err := io.Copy(tf, r); err != nil {
		tf.Close()
		return nil, hint, fmt.Errorf("alpine: unable to copy resp body to tempfile: %w", err)
	}
	if n, err := tf.Seek(0, io.SeekStart); err != nil || n != 0 {
		tf.Close()
		return nil, hint, fmt.Errorf("alpine: unable to seek database to start: at %d, %v", n, err)
	}
	zlog.Debug(ctx).Msg("decompressed and buffered database")

	hint = driver.Fingerprint(res.Header.Get("etag"))
	zlog.Debug(ctx).
		Str("hint", string(hint)).
		Msg("using new hint")

	return tf, hint, nil
}
