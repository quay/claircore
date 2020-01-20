package oracle

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var eightOSRelease []byte = []byte(`NAME="Oracle Linux Server"
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

var eightOSReleaseBad []byte = []byte(`NAME="Oracle Linux Server"
VERSION="8.0"
ID="ol"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="8.0"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Oracle Linux Server"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:8:0:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://bugzilla.oracle.com/"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 8"
ORACLE_BUGZILLA_PRODUCT_VERSION=8.0
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=8.0`)

var sevenOSRelease []byte = []byte(`NAME="Oracle Linux Server"
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

var sevenOSReleaseBad []byte = []byte(`NAME="Oracle Linux Server"
VERSION="7.7"
ID="ol"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="7.7"
PRETTY_NAME="Oracle Linux Server"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:7:7:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://bugzilla.oracle.com/"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 7"
ORACLE_BUGZILLA_PRODUCT_VERSION=7.7
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=7.7`)

var sixOSRelease []byte = []byte(`NAME="Oracle Linux Server"
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

var sixOSReleaseBad []byte = []byte(`NAME="Oracle Linux Server"
VERSION="6.10"
ID="ol"
VERSION_ID="6.10"
PRETTY_NAME="Oracle Linux Server"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:6:10:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://bugzilla.oracle.com/"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 6"
ORACLE_BUGZILLA_PRODUCT_VERSION=6.10
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=6.10`)

// Oracle Five versions do not have os-release file and only have /etc/issue file
var fiveIssue []byte = []byte(`
Oracle Linux Server release 5.11
Kernel \r on an \m
`)

var fiveIssueBad []byte = []byte(`
Oracle Linux Server release
Kernel \r on an \m
`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name    string
		release Release
		file    []byte
	}{
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

func TestDistributionScannerBad(t *testing.T) {
	table := []struct {
		name    string
		release Release
		file    []byte
	}{
		{
			name:    "8.0",
			release: Eight,
			file:    eightOSReleaseBad,
		},
		{
			name:    "7.7",
			release: Seven,
			file:    sevenOSReleaseBad,
		},
		{
			name:    "6.10",
			release: Six,
			file:    sixOSReleaseBad,
		},
		{
			name:    "5.11",
			release: Five,
			file:    fiveIssueBad,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.file))
			if dist != nil {
				t.Fatalf("expected nil dist got %v", dist)
			}
		})
	}
}
