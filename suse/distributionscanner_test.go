package suse

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
)

var enterpriseServer15OSRelease []byte = []byte(`NAME="SLES"
VERSION="15-SP1"
VERSION_ID="15.1"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP1"
ID="sles"
ID_LIKE="suse"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sles:15:sp1"`)

var enterpriseServer12OSRelease []byte = []byte(`NAME="SLES"
VERSION="12-SP5"
VERSION_ID="12.5"
PRETTY_NAME="SUSE Linux Enterprise Server 12 SP5"
ID="sles"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sles:12:sp5"`)

var leap15OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="15.0"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.0"
PRETTY_NAME="openSUSE Leap 15.0"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.0"
BUG_REPORT_URL="https://bugs.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

var leap151OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="15.1"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.1"
PRETTY_NAME="openSUSE Leap 15.1"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.1"
BUG_REPORT_URL="https://bugs.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

func TestDistributionScanner(t *testing.T) {
	ctx := context.Background()
	table := []struct {
		name      string
		dist      *claircore.Distribution
		osRelease []byte
	}{
		{
			name:      "enterprise server 15",
			osRelease: enterpriseServer15OSRelease,
			dist: &claircore.Distribution{
				DID:        "sles",
				Name:       "SLES",
				Version:    "15",
				VersionID:  "15",
				PrettyName: "SUSE Linux Enterprise Server 15",
			},
		},
		{
			name:      "enterprise server 12",
			osRelease: enterpriseServer12OSRelease,
			dist: &claircore.Distribution{
				DID:        "sles",
				Name:       "SLES",
				Version:    "12",
				VersionID:  "12",
				PrettyName: "SUSE Linux Enterprise Server 12",
			},
		},
		{
			name:      "leap 15.0",
			osRelease: leap15OSRelease,
			dist: &claircore.Distribution{
				DID:        "opensuse-leap",
				Name:       "openSUSE Leap",
				Version:    "15.0",
				VersionID:  "15.0",
				PrettyName: "openSUSE Leap 15.0",
			},
		},
		{
			name:      "leap 15.1",
			osRelease: leap151OSRelease,
			dist: &claircore.Distribution{
				DID:        "opensuse-leap",
				Name:       "openSUSE Leap",
				Version:    "15.1",
				VersionID:  "15.1",
				PrettyName: "openSUSE Leap 15.1",
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(ctx, bytes.NewBuffer(tt.osRelease))
			if !cmp.Equal(dist, tt.dist) {
				t.Fatalf("%v", cmp.Diff(dist, tt.dist))
			}
		})
	}
}
