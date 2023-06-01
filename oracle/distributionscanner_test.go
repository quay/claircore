package oracle

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var (
	nineOSRelease = []byte(`NAME="Oracle Linux Server"
VERSION="9.2"
ID="ol"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="9.2"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Oracle Linux Server 9.2"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:9:2:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://github.com/oracle/oracle-linux"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 9"
ORACLE_BUGZILLA_PRODUCT_VERSION=9.2
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=9.2`)

	eightOSRelease = []byte(`NAME="Oracle Linux Server"
VERSION="8.0"
ID="ol"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="8.0"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Oracle Linux Server 8.0"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:8:0:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://bugzilla.oracle.com/"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 8"
ORACLE_BUGZILLA_PRODUCT_VERSION=8.0
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=8.0`)

	sevenOSRelease = []byte(`NAME="Oracle Linux Server"
VERSION="7.7"
ID="ol"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="7.7"
PRETTY_NAME="Oracle Linux Server 7.7"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:7:7:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://bugzilla.oracle.com/"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 7"
ORACLE_BUGZILLA_PRODUCT_VERSION=7.7
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=7.7`)

	sixOSRelease = []byte(`NAME="Oracle Linux Server"
VERSION="6.10"
ID="ol"
VERSION_ID="6.10"
PRETTY_NAME="Oracle Linux Server 6.10"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:6:10:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://bugzilla.oracle.com/"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 6"
ORACLE_BUGZILLA_PRODUCT_VERSION=6.10
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=6.10`)

	// Oracle Five versions do not have os-release file and only have /etc/issue file
	fiveIssue = []byte(`
Oracle Linux Server release 5.11
Kernel \r on an \m
`)
)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name    string
		release Release
		file    []byte
	}{
		{
			name:    "9.2",
			release: Nine,
			file:    nineOSRelease,
		},
		{
			name:    "8.0",
			release: Eight,
			file:    eightOSRelease,
		},
		{
			name:    "7.7",
			release: Seven,
			file:    sevenOSRelease,
		},
		{
			name:    "6.10",
			release: Six,
			file:    sixOSRelease,
		},
		{
			name:    "5.11",
			release: Five,
			file:    fiveIssue,
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
