package bom

import (
	"unique"

	"github.com/CycloneDX/cyclonedx-go"
)

var hashnames = map[cyclonedx.HashAlgorithm]unique.Handle[string]{
	cyclonedx.HashAlgoSHA256: HashSHA256,
	cyclonedx.HashAlgoSHA1:   HashSHA1,
}

// Known hash kinds.
var (
	HashSHA1   = unique.Make(`sha1`)
	HashSHA256 = unique.Make(`sha256`)
)
