package photon

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var photon1OSRelease []byte = []byte(`NAME="VMware Photon"
VERSION="1.0"
ID=photon
VERSION_ID="1.0"
PRETTY_NAME="VMware Photon/Linux"
ANSI_COLOR="1;34"
HOME_URL="https://vmware.github.io/photon/"
BUG_REPORT_URL="https://github.com/vmware/photon/issues"`)

var photon2OSRelease []byte = []byte(`NAME="VMware Photon OS"
VERSION="2.0"
ID=photon
VERSION_ID="2.0"
PRETTY_NAME="VMware Photon OS/Linux"
ANSI_COLOR="1;34"
HOME_URL="https://vmware.github.io/photon/"
BUG_REPORT_URL="https://github.com/vmware/photon/issues"`)

var photon3OSRelease []byte = []byte(`NAME="VMware Photon OS"
VERSION="3.0"
ID=photon
VERSION_ID="3.0"
PRETTY_NAME="VMware Photon OS/Linux"
ANSI_COLOR="1;34"
HOME_URL="https://vmware.github.io/photon/"
BUG_REPORT_URL="https://github.com/vmware/photon/issues"`)

var photon4OSRelease []byte = []byte(`NAME="VMware Photon OS"
VERSION="4.0"
ID=photon
VERSION_ID="4.0"
PRETTY_NAME="VMware Photon OS/Linux"
ANSI_COLOR="1;34"
HOME_URL="https://vmware.github.io/photon/"
BUG_REPORT_URL="https://github.com/vmware/photon/issues"`)

var photon5OSRelease []byte = []byte(`NAME="VMware Photon OS"
VERSION="5.0"
ID=photon
VERSION_ID="5.0"
PRETTY_NAME="VMware Photon OS/Linux"
ANSI_COLOR="1;34"
HOME_URL="https://vmware.github.io/photon/"
BUG_REPORT_URL="https://github.com/vmware/photon/issues"`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name      string
		release   Release
		osRelease []byte
	}{
		{
			name:      "photon 1.0",
			release:   Photon1,
			osRelease: photon1OSRelease,
		},
		{
			name:      "photon 2.0",
			release:   Photon2,
			osRelease: photon2OSRelease,
		},
		{
			name:      "photon 3.0",
			release:   Photon3,
			osRelease: photon3OSRelease,
		},
		{
			name:      "photon 4.0",
			release:   Photon4,
			osRelease: photon4OSRelease,
		},
		{
			name:      "photon 5.0",
			release:   Photon5,
			osRelease: photon5OSRelease,
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
