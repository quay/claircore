package ovalutil

import "github.com/quay/goval-parser/oval"

// ArchMatch checks if given package arch match with requited arch based on operator
func ArchMatch(pkgArch string, requiredPkgArch string, operation oval.Operation) bool {
	if requiredPkgArch == "" {
		return true
	}
	if pkgArch == "" {
		return false
	}
	return Operation(pkgArch, requiredPkgArch, operation)
}
