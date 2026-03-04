package wart

import "github.com/quay/claircore/toolkit/types"

// StringFromPackageKind maps the [types.PackageKind] to the untyped string
// representation that used to be used in [claircore.Package] objects.
//
// A [types.UnknownPackage] value becomes "".
func StringFromPackageKind(k types.PackageKind) string {
	if k == types.UnknownPackage {
		return ""
	}
	return k.String()
}

// PackageKindFromString does (approximately) the inverse of [StringFromPackageKind].
//
// The "normal" [fmt.Stringer] values map back to the correct type, and the
// empty string maps to [types.UnknownPackage].
func PackageKindFromString(k string) types.PackageKind {
	switch k {
	case "ancestry":
		return types.AncestryPackage
	case "layer":
		return types.LayerPackage
	case "source":
		return types.SourcePackage
	case "binary":
		return types.BinaryPackage
	default:
		return types.UnknownPackage
	}
}

// BUG(hank) With [types.PackageKind], the explicit "unknown" value means the
// empty string semantics change. There's obviously no way to keep arbitrary
// values through the enum, but this package's [StringFromPackageKind] and
// [PackageKindFromString] shims translate [types.UnknownPackage] to and from
// the empty string.
//
// Fixing this "properly" at the database layer would involve a costly
// migration; hence the wart.
