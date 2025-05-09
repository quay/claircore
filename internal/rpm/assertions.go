package rpm

import (
	"github.com/quay/claircore/internal/rpm/bdb"
	"github.com/quay/claircore/internal/rpm/ndb"
	"github.com/quay/claircore/internal/rpm/sqlite"
)

// Assert that the various database-specific packages implement [HeaderReader].
var (
	_ HeaderReader = (*sqlite.RPMDB)(nil)
	_ HeaderReader = (*bdb.PackageDB)(nil)
	_ HeaderReader = (*ndb.PackageDB)(nil)
)
