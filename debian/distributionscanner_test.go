package debian

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var busterOSRelease []byte = []byte(`PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"`)

var busterOSReleaseBad []byte = []byte(`PRETTY_NAME="Debian GNU/Linux"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"`)

var busterIssue []byte = []byte(`Debian GNU/Linux 10 \n \l`)

var busterIssueBad []byte = []byte(`Debian GNU/Linux \n \l`)

var jessieOSRelease []byte = []byte(`PRETTY_NAME="Debian GNU/Linux 8 (jessie)"
NAME="Debian GNU/Linux"
VERSION_ID="8"
VERSION="8 (jessie)"
ID=debian
HOME_URL="http://www.debian.org/"
SUPPORT_URL="http://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"`)

var jessieOSReleaseBad []byte = []byte(`PRETTY_NAME="Debian GNU/Linux"
NAME="Debian GNU/Linux"
VERSION_ID="8"
VERSION="8 (jessie)"
ID=debian
HOME_URL="http://www.debian.org/"
SUPPORT_URL="http://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"`)

var jessieIssue []byte = []byte(`Debian GNU/Linux 8 \n \l`)

var jessieIssueBad []byte = []byte(`Debian GNU/Linux \n \l`)

var stretchOSRelease []byte = []byte(`PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
NAME="Debian GNU/Linux"
VERSION_ID="9"
VERSION="9 (stretch)"
VERSION_CODENAME=stretch
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"`)

var stretchOSReleaseBad []byte = []byte(`PRETTY_NAME="Debian GNU/Linux"
NAME="Debian GNU/Linux"
VERSION_ID="9"
VERSION="9 (stretch)"
VERSION_CODENAME=stretch
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"`)

var stretchIssue []byte = []byte(`Debian GNU/Linux 9 \n \l`)

var stretchIssueBad []byte = []byte(`Debian GNU/Linux`)

var wheezyOSRelease []byte = []byte(`PRETTY_NAME="Debian GNU/Linux 7 (wheezy)"
NAME="Debian GNU/Linux"
VERSION_ID="7"
VERSION="7 (wheezy)"
ID=debian
ANSI_COLOR="1;31"
HOME_URL="http://www.debian.org/"
SUPPORT_URL="http://www.debian.org/support/"
BUG_REPORT_URL="http://bugs.debian.org/"`)

var wheezyOSReleaseBad []byte = []byte(`PRETTY_NAME="Debian GNU/Linux"
NAME="Debian GNU/Linux"
VERSION_ID="7"
VERSION="7 (wheezy)"
ID=debian
ANSI_COLOR="1;31"
HOME_URL="http://www.debian.org/"
SUPPORT_URL="http://www.debian.org/support/"
BUG_REPORT_URL="http://bugs.debian.org/"`)

var wheezyIssue []byte = []byte(`Debian GNU/Linux 7 \n \l`)

var wheezyIssueBad []byte = []byte(`Debian GNU/Linux`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name      string
		release   Release
		osRelease []byte
		issue     []byte
	}{
		{
			name:      "buster",
			release:   Buster,
			osRelease: busterOSRelease,
			issue:     busterIssue,
		},
		{
			name:      "jessie",
			release:   Jessie,
			osRelease: jessieOSRelease,
			issue:     jessieIssue,
		},
		{
			name:      "stretch",
			release:   Stretch,
			osRelease: stretchOSRelease,
			issue:     stretchIssue,
		},
		{
			name:      "wheezy",
			release:   Wheezy,
			osRelease: wheezyOSRelease,
			issue:     wheezyIssue,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.osRelease))
			if !cmp.Equal(dist, releaseToDist(tt.release)) {
				t.Fatalf("%v", cmp.Diff(dist, releaseToDist(tt.release)))
			}
			dist = scanner.parse(bytes.NewBuffer(tt.issue))
			if !cmp.Equal(dist, releaseToDist(tt.release)) {
				t.Fatalf("%v", cmp.Diff(dist, releaseToDist(tt.release)))
			}
		})
	}
}

func TestDistributionScannerBad(t *testing.T) {
	table := []struct {
		name      string
		release   Release
		osRelease []byte
		issue     []byte
	}{
		{
			name:      "buster",
			release:   Buster,
			osRelease: busterOSReleaseBad,
			issue:     busterIssueBad,
		},
		{
			name:      "jessie",
			release:   Jessie,
			osRelease: jessieOSReleaseBad,
			issue:     jessieIssueBad,
		},
		{
			name:      "stretch",
			release:   Stretch,
			osRelease: stretchOSReleaseBad,
			issue:     stretchIssueBad,
		},
		{
			name:      "wheezy",
			release:   Wheezy,
			osRelease: wheezyOSReleaseBad,
			issue:     wheezyIssueBad,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.osRelease))
			if dist != nil {
				t.Fatalf("expected dist to be nil but got: %v", dist)
			}
			dist = scanner.parse(bytes.NewBuffer(tt.issue))
			if dist != nil {
				t.Fatalf("expected dist to be nil but got: %v", dist)
			}
		})
	}
}
