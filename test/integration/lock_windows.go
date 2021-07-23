package integration

import "testing"

// BUG(hank) The windows implementation of the file locking is non-fuctional. We
// only build the clair client binaries on windows, so this shouldn't matter.
// If anyone wants to actually run clair on windows, this should be fixed so
// that the tests don't flake.

func lockDir(_ testing.TB, _ string) (excl bool) { return true }

func lockDirShared(_ testing.TB, _ string) {}
