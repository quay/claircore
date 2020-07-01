package pyupio

import (
	"context"
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/python"
)

func UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	repo := python.Repository
	py, err := NewUpdater(WithRepo(&repo))
	if err != nil {
		return us, fmt.Errorf("failed to create pyupio updater: %v", err)
	}
	err = us.Add(py)
	if err != nil {
		return us, err
	}
	return us, nil
}
