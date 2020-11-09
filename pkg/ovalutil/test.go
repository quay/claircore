package ovalutil

import (
	"fmt"

	"github.com/quay/goval-parser/oval"
)

// TestLookup is a general test lookup function.
//
// The passed function can be used as an allowlist for test kinds. All known
// kinds will be returned if not provided.
func TestLookup(root *oval.Root, ref string, f func(kind string) bool) (oval.Test, error) {
	kind, i, err := root.Tests.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if f != nil && !f(kind) {
		return nil, fmt.Errorf("disallowed kind %q: %w", kind, errTestSkip)
	}
	switch kind {
	case "dpkginfo_test":
		return &root.Tests.DpkgInfoTests[i], nil
	case "line_test":
		return &root.Tests.LineTests[i], nil
	case "rpminfo_test":
		return &root.Tests.RPMInfoTests[i], nil
	case "rpmverifyfile_test":
		return &root.Tests.RPMVerifyFileTests[i], nil
	case "textfilecontent54_test":
		return &root.Tests.TextfileContent54Tests[i], nil
	case "uname_test":
		return &root.Tests.UnameTests[i], nil
	case "version55_test":
		return &root.Tests.Version55Tests[i], nil
	}
	return nil, fmt.Errorf("unknown kind: %q", kind)
}
