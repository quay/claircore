package oracle

import (
	"context"
	"fmt"
	"time"

	"github.com/quay/claircore/libvuln/driver"
)

func UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	us := driver.NewUpdaterSet()
	for year, lim := 2007, time.Now().Year(); year != lim; year++ {
		u, err := NewUpdater(year)
		if err != nil {
			return us, fmt.Errorf("unable to create oracle updater: %v", err)
		}
		err = us.Add(u)
		if err != nil {
			return us, err
		}
	}
	return us, nil
}
