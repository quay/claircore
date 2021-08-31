package rhel

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var rhel3RHRelease []byte = []byte(`Red Hat Enterprise Linux Server release 3.1 (Taroon)`)
var rhel4RHRelease []byte = []byte(`Red Hat Enterprise Linux Server release 4.8 (Nahant)`)
var rhel5RHRelease []byte = []byte(`Red Hat Enterprise Linux Server release 5.6 (Tikanga)`)
var rhel6RHRelease []byte = []byte(`Red Hat Enterprise Linux Server release 6.10 (Santiago)`)
var rhel7RHRelease []byte = []byte(`Red Hat Enterprise Linux Server release 7.4 (Maipo)`)
var rhel7OSRelease []byte = []byte(`NAME="Red Hat Enterprise Linux Server"
VERSION="7.7 (Maipo)"
ID="rhel"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="7.7"
PRETTY_NAME="Red Hat Enterprise Linux Server 7.7 (Maipo)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:7.7:GA:server"
HOME_URL="https://access.redhat.com/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"

REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 7"
REDHAT_BUGZILLA_PRODUCT_VERSION=7.7
REDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="7.7"`)
var rhel8RHRelease []byte = []byte(`Red Hat Enterprise Linux Server release 8.1 (Ootpa)`)
var rhel8OSRelease []byte = []byte(`NAME="Red Hat Enterprise Linux"
VERSION="8.1 (Ootpa)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="8.1"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Red Hat Enterprise Linux 8.1 (Ootpa)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:8.1:GA"
HOME_URL="https://access.redhat.com/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"

REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 8"
REDHAT_BUGZILLA_PRODUCT_VERSION=8.1
REDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="8.1"`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name    string
		release Release
		file    []byte
	}{
		{
			name:    "RHEL3",
			release: RHEL3,
			file:    rhel3RHRelease,
		},
		{
			name:    "RHEL4",
			release: RHEL4,
			file:    rhel4RHRelease,
		},
		{
			name:    "RHEL5",
			release: RHEL5,
			file:    rhel5RHRelease,
		},
		{
			name:    "RHEL6",
			release: RHEL6,
			file:    rhel6RHRelease,
		},
		{
			name:    "RHEL7",
			release: RHEL7,
			file:    rhel7RHRelease,
		},
		{
			name:    "RHEL7 OSRelease",
			release: RHEL7,
			file:    rhel7OSRelease,
		},
		{
			name:    "RHEL8",
			release: RHEL8,
			file:    rhel8RHRelease,
		},
		{
			name:    "RHEL8 OSRelease",
			release: RHEL8,
			file:    rhel8OSRelease,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.file))
			if !cmp.Equal(dist, releaseToDist(tt.release)) {
				t.Fatalf("%v", cmp.Diff(dist, releaseToDist(tt.release)))
			}
		})
	}
}
