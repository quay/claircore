package aws

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var AL1v201609OSRelease []byte = []byte(`NAME="Amazon Linux AMI"
VERSION="2016.09"
ID="amzn"
ID_LIKE="rhel fedora"
VERSION_ID="2016.09"
PRETTY_NAME="Amazon Linux AMI 2016.09"
ANSI_COLOR="0;33"
CPE_NAME="cpe:/o:amazon:linux:2016.09:ga"
HOME_URL="http://aws.amazon.com/amazon-linux-ami/"`)

var AL1v201703OSRelease []byte = []byte(`NAME="Amazon Linux AMI"
VERSION="2017.03"
ID="amzn"
ID_LIKE="rhel fedora"
VERSION_ID="2017.03"
PRETTY_NAME="Amazon Linux AMI 2017.03"
ANSI_COLOR="0;33"
CPE_NAME="cpe:/o:amazon:linux:2017.03:ga"
HOME_URL="http://aws.amazon.com/amazon-linux-ami/"`)

var AL1v201709OSRelease []byte = []byte(`NAME="Amazon Linux AMI"
VERSION="2017.09"
ID="amzn"
ID_LIKE="rhel fedora"
VERSION_ID="2017.09"
PRETTY_NAME="Amazon Linux AMI 2017.09"
ANSI_COLOR="0;33"
CPE_NAME="cpe:/o:amazon:linux:2017.09:ga"
HOME_URL="http://aws.amazon.com/amazon-linux-ami/"`)

var AL1v201803OSRelease []byte = []byte(`NAME="Amazon Linux AMI"
VERSION="2018.03"
ID="amzn"
ID_LIKE="rhel fedora"
VERSION_ID="2018.03"
PRETTY_NAME="Amazon Linux AMI 2018.03"
ANSI_COLOR="0;33"
CPE_NAME="cpe:/o:amazon:linux:2018.03:ga"
HOME_URL="http://aws.amazon.com/amazon-linux-ami/"`)

var AL2OSRelease []byte = []byte(`NAME="Amazon Linux"
VERSION="2"
ID="amzn"
ID_LIKE="centos rhel fedora"
VERSION_ID="2"
PRETTY_NAME="Amazon Linux 2"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2"
HOME_URL="https://amazonlinux.com/"`)

var AL2023OSRelease []byte = []byte(`NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2023"
HOME_URL="https://aws.amazon.com/linux/"
BUG_REPORT_URL="https://github.com/amazonlinux/amazon-linux-2023"
SUPPORT_END="2028-03-01"`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name      string
		release   Release
		osRelease []byte
		prettyDistName string
	}{
		{
			name:      "AL1",
			release:   AmazonLinux1,
			osRelease: AL1v201609OSRelease,
			prettyDistName: "Amazon Linux AMI 2018.03",
		},
		{
			name:      "AL1",
			release:   AmazonLinux1,
			osRelease: AL1v201703OSRelease,
			prettyDistName: "Amazon Linux AMI 2018.03",
		},
		{
			name:      "AL1",
			release:   AmazonLinux1,
			osRelease: AL1v201709OSRelease,
			prettyDistName: "Amazon Linux AMI 2018.03",
		},
		{
			name:      "AL1",
			release:   AmazonLinux1,
			osRelease: AL1v201803OSRelease,
			prettyDistName: "Amazon Linux AMI 2018.03",
		},
		{
			name:      "AL2",
			release:   AmazonLinux2,
			osRelease: AL2OSRelease,
			prettyDistName: "Amazon Linux 2",
		},
		{
			name:      "AL2023",
			release:   AmazonLinux2023,
			osRelease: AL2023OSRelease,
			prettyDistName: "Amazon Linux 2023",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.osRelease))
			cmpDist := releaseToDist(tt.release)
			if !cmp.Equal(dist, cmpDist) {
				t.Fatalf("%v", cmp.Diff(dist, cmpDist))
			}
			if !cmp.Equal(cmpDist.PrettyName, tt.prettyDistName) {
				t.Fatalf("%v", cmp.Diff(tt.prettyDistName, cmpDist.PrettyName))
			}
		})
	}
}
