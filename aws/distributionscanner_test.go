package aws

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var linux1OSRelease []byte = []byte(`NAME="Amazon Linux AMI"
VERSION="2018.03"
ID="amzn"
ID_LIKE="rhel fedora"
VERSION_ID="2018.03"
PRETTY_NAME="Amazon Linux AMI 2018.03"
ANSI_COLOR="0;33"
CPE_NAME="cpe:/o:amazon:linux:2018.03:ga"
HOME_URL="http://aws.amazon.com/amazon-linux-ami/"`)

var linux2OSRelease []byte = []byte(`NAME="Amazon Linux"
VERSION="2"
ID="amzn"
ID_LIKE="centos rhel fedora"
VERSION_ID="2"
PRETTY_NAME="Amazon Linux 2"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2"
HOME_URL="https://amazonlinux.com/"`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name      string
		release   Release
		osRelease []byte
	}{
		{
			name:      "linux1",
			release:   Linux1,
			osRelease: linux1OSRelease,
		},
		{
			name:      "linux2",
			release:   Linux2,
			osRelease: linux2OSRelease,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.osRelease))
			cmpDist, _ := releaseToDist(tt.release)
			if !cmp.Equal(dist, cmpDist) {
				t.Fatalf("%v", cmp.Diff(dist, cmpDist))
			}
		})
	}
}
