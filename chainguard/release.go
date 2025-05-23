package chainguard

import (
	"github.com/quay/claircore"
)

var chainguardDist = &claircore.Distribution{
	Name: "chainguard",
	DID:  "chainguard",
	// Chainguard images are not versioned.
	// Explicitly set the version to the empty string for clarity.
	// See https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/scanning_implementation.md#chainguards-distros-are-not-versioned
	// for more information.
	Version:    "",
	PrettyName: "Chainguard",
}

var wolfiDist = &claircore.Distribution{
	Name: "wolfi",
	DID:  "wolfi",
	// Wolfi images are not versioned.
	// Explicitly set the version to the empty string for clarity.
	// See https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/scanning_implementation.md#chainguards-distros-are-not-versioned
	// for more information.
	Version:    "",
	PrettyName: "Wolfi",
}
