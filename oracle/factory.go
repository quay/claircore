package oracle

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/quay/claircore/libvuln/driver"
)

// FactoryConfig configures the Oracle Factory.
type FactoryConfig struct {
	// URL indicates the index root. It should have a trailing slash.
	URL string `json:"url" yaml:"url"`
}

// indexURL is the Oracle OVAL index root.
//
//doc:url updater
const indexURL = `https://linux.oracle.com/security/oval/`

// Factory provides a driver.UpdaterSetFactory for Oracle with an injected client.
type Factory struct {
	c    *http.Client
	base string
}

// Configure implements driver.Configurable.
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		f.base = cfg.URL
	} else {
		f.base = indexURL
	}
	return nil
}

// UpdaterSet implements driver.UpdaterSetFactory with inlined discovery logic.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()

	cl := f.c
	if cl == nil {
		slog.InfoContext(ctx, "unconfigured")
		return us, nil
	}
	base := f.base
	if base == "" {
		base = indexURL
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return us, fmt.Errorf("oracle: unable to construct request: %w", err)
	}
	res, err := cl.Do(req)
	if err != nil {
		return us, fmt.Errorf("oracle: error requesting %q: %w", base, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return us, fmt.Errorf("oracle: unexpected status requesting OVAL dir: %v", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return us, fmt.Errorf("oracle: unable to read index body: %w", err)
	}
	re := regexp.MustCompile(`href="(com\.oracle\.elsa-(\d{4})\.xml\.bz2)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		return us, fmt.Errorf("oracle: no OVAL entries discovered at index")
	}
	seen := map[int]struct{}{}
	cutoff := time.Now().Year() - 9
	for _, m := range matches {
		var y int
		fmt.Sscanf(m[2], "%d", &y)
		if y < cutoff {
			continue
		}
		if _, ok := seen[y]; ok {
			continue
		}
		seen[y] = struct{}{}
		uri := base + m[1]
		up, err := NewUpdater(y, WithURL(uri, "bzip2"))
		if err != nil {
			return us, fmt.Errorf("oracle: unable to create updater for %d: %w", y, err)
		}
		if err := us.Add(up); err != nil {
			return us, err
		}
		slog.DebugContext(ctx, "oracle: added updater", "name", up.Name())
	}
	return us, nil
}
