package photon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/quay/claircore/libvuln/driver"
)

// UpdaterSet dynamically discovers available Photon OVAL databases from the
// upstream index and returns one updater per discovered major release.
//
// Discovery rules:
// - Match files named com.vmware.phsa-photon<MAJOR>.xml.gz
func UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()

	res, err := http.DefaultClient.Get(upstreamBase.String())
	if err != nil {
		return us, fmt.Errorf("photon: discovery request failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return us, fmt.Errorf("photon: unexpected status from index: %s", res.Status)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return us, fmt.Errorf("photon: reading index body: %w", err)
	}

	re := regexp.MustCompile(`href="com\.vmware\.phsa-photon(\d+)\.xml\.gz"`)
	matches := re.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		return us, fmt.Errorf("photon: no OVAL entries discovered at index")
	}
	for _, m := range matches {
		fmt.Println(m)
		if len(m) < 2 {
			continue
		}
		major := m[1]
		rel := Release(major + ".0")
		up, err := NewUpdater(rel)
		if err != nil {
			return us, fmt.Errorf("photon: creating updater for %s: %w", rel, err)
		}
		if err := us.Add(up); err != nil {
			return us, err
		}
	}
	return us, nil
}
