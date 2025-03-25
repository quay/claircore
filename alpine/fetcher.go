package alpine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

func (u *updater) Fetch(ctx context.Context, hint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	slog.InfoContext(ctx, "starting fetch", "database", u.url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to construct request: %w", err)
	}

	if hint != "" {
		slog.DebugContext(ctx,
			"using hint",
			"hint", string(hint))
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
		slog.InfoContext(ctx, "database unchanged since last fetch")
		return nil, hint, driver.Unchanged
	default:
		return nil, hint, fmt.Errorf("alpine: http response error: %s %d", res.Status, res.StatusCode)
	}
	slog.DebugContext(ctx, "successfully requested database")

	tf, err := tmp.NewFile("", u.Name()+".")
	if err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to open tempfile: %w", err)
	}
	slog.DebugContext(ctx,
		"created tempfile",
		"name", tf.Name())
	var success bool
	defer func() {
		if !success {
			if err := tf.Close(); err != nil {
				slog.WarnContext(ctx,
					"unable to close spool",
					"reason", err)
			}
		}
	}()

	var r io.Reader = res.Body
	if _, err := io.Copy(tf, r); err != nil {
		return nil, hint, fmt.Errorf("alpine: unable to copy resp body to tempfile: %w", err)
	}
	if n, err := tf.Seek(0, io.SeekStart); err != nil || n != 0 {
		return nil, hint, fmt.Errorf("alpine: unable to seek database to start: at %d, %v", n, err)
	}
	slog.DebugContext(ctx, "decompressed and buffered database")

	success = true
	hint = driver.Fingerprint(res.Header.Get("etag"))
	slog.DebugContext(ctx,
		"using new hint",
		"hint", string(hint))

	return tf, hint, nil
}
