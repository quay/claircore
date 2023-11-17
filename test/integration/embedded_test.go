package integration

import (
	"testing"
)

func TestDiscover(t *testing.T) {
	Skip(t)

	f := fetchDescriptor{
		OS:      "linux",
		Arch:    "amd64",
		Version: "15",
	}
	f.DiscoverVersion(t)
}
