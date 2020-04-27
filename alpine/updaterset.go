package alpine

import (
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
)

var alpineMatrix = map[Repo][]Release{
	Main:      []Release{V3_10, V3_9, V3_8, V3_7, V3_6, V3_5, V3_4, V3_3},
	Community: []Release{V3_10, V3_9, V3_8, V3_7, V3_6, V3_5, V3_4, V3_3},
}

func UpdaterSet() (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for repo, releases := range alpineMatrix {
		for _, release := range releases {
			u, err := NewUpdater(release, repo)
			if err != nil {
				return us, fmt.Errorf("failed to create updater: %v %v", release, repo)
			}
			err = us.Add(u)
			if err != nil {
				return us, err
			}
		}
	}
	return us, nil
}
