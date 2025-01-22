package rpm

import (
	"github.com/quay/claircore/internal/rpm/bdb"
	"github.com/quay/claircore/internal/rpm/ndb"
	"github.com/quay/claircore/internal/rpm/sqlite"
)

// Assert that the nativeAdapter implements [NativeDB].
var _ NativeDB = (*nativeAdapter)(nil)

// Assert that the various database-specific packages implement [innerDB].
var (
	_ innerDB = (*sqlite.RPMDB)(nil)
	_ innerDB = (*bdb.PackageDB)(nil)
	_ innerDB = (*ndb.PackageDB)(nil)
)
