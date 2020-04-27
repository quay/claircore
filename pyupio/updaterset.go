package pyupio

import (
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
)

func UpdaterSet() (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	py, err := NewUpdater()
	if err != nil {
		return us, fmt.Errorf("failed to create pyupio updater: %v", err)
	}
	err = us.Add(py)
	if err != nil {
		return us, err
	}
	return us, nil
}
