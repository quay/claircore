package suse

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var enterpriseServer15OSRelease []byte = []byte(`NAME="SLES"
VERSION="15-SP4"
VERSION_ID="15.1"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP4"
ID="sles"
ID_LIKE="suse"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sles:15:sp4"`)

var enterpriseServer12OSRelase []byte = []byte(`NAME="SLES"
VERSION="12-SP5"
VERSION_ID="12.5"
PRETTY_NAME="SUSE Linux Enterprise Server 12 SP5"
ID="sles"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sles:12:sp5"`)

var enterpriseServer11OSRelease []byte = []byte(`NAME="SLES"
VERSION="11-SP5"
VERSION_ID="11.2"
PRETTY_NAME="SUSE Linux Enterprise Server 11 SP5"
ID="sles"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sles:12:sp5"`)

var leap154OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="15.4"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.4"
PRETTY_NAME="openSUSE Leap 15.4"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.4"
BUG_REPORT_URL="https://bugzilla.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

var leap153OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="15.3"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.3"
PRETTY_NAME="openSUSE Leap 15.3"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.3"
BUG_REPORT_URL="https://bugzilla.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

var leap152OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="15.2"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.2"
PRETTY_NAME="openSUSE Leap 15.2"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.2"
BUG_REPORT_URL="https://bugzilla.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

var leap151OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="15.1"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.1"
PRETTY_NAME="openSUSE Leap 15.1"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.1"
BUG_REPORT_URL="https://bugzilla.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

var leap15OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="15.0"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.0"
PRETTY_NAME="openSUSE Leap 15.0"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.0"
BUG_REPORT_URL="https://bugzilla.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

var leap423OSRelease []byte = []byte(`NAME="openSUSE Leap"
VERSION="42.3"
ID=opensuse
ID_LIKE="suse"
VERSION_ID="42.3"
PRETTY_NAME="openSUSE Leap 42.3"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:42.3"
BUG_REPORT_URL="https://bugzilla.opensuse.org"
HOME_URL="https://www.opensuse.org/"`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name      string
		release   Release
		osRelease []byte
	}{
		{
			name:      "enterprise server 15",
			release:   EnterpriseServer15,
			osRelease: enterpriseServer15OSRelease,
		},
		{
			name:      "enterprise server 12",
			release:   EnterpriseServer12,
			osRelease: enterpriseServer12OSRelase,
		},
		{
			name:      "enterprise server 11",
			release:   EnterpriseServer11,
			osRelease: enterpriseServer11OSRelease,
		},
		{
			name:      "leap 15.4",
			release:   Leap154,
			osRelease: leap154OSRelease,
		},
		{
			name:      "leap 15.3",
			release:   Leap153,
			osRelease: leap153OSRelease,
		},
		{
			name:      "leap 15.2",
			release:   Leap152,
			osRelease: leap152OSRelease,
		},
		{
			name:      "leap 15.1",
			release:   Leap151,
			osRelease: leap151OSRelease,
		},
		{
			name:      "leap 15.0",
			release:   Leap150,
			osRelease: leap15OSRelease,
		},
		{
			name:      "leap 42.3",
			release:   Leap423,
			osRelease: leap423OSRelease,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.osRelease))
			if !cmp.Equal(dist, releaseToDist(tt.release)) {
				t.Fatalf("%v", cmp.Diff(dist, releaseToDist(tt.release)))
			}
		})
	}
}
