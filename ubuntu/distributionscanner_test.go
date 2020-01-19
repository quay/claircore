package ubuntu

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// artful test data
var artfulOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="17.10 (Artful Aardvark)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 17.10"
VERSION_ID="17.10"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=artful
UBUNTU_CODENAME=artful`)

var artfulOSReleaseBad []byte = []byte(`NAME="Ubuntu"
VERSION="17.10 ( Aardvark)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 17.10"
VERSION_ID="17.10"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=
UBUNTU_CODENAME=`)

var artfulLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=17.10
DISTRIB_CODENAME=artful
DISTRIB_DESCRIPTION="Ubuntu 17.10"`)

var artfulLSBReleaseBad []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=17.10
DISTRIB_CODENAME=
DISTRIB_DESCRIPTION="Ubuntu 17.10"`)

// bionic test data
var bionicOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="18.04.3 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.3 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic`)

var bionicOSReleaseBad []byte = []byte(`NAME="Ubuntu"
VERSION="18.04.3 LTS ( Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.3 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=
UBUNTU_CODENAME=`)

var bionicLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.3 LTS"`)

var bionicLSBReleaseBad []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=
DISTRIB_DESCRIPTION="Ubuntu 18.04.3 LTS"`)

// cosmic test data
var cosmicOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="18.10 (Cosmic Cuttlefish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.10"
VERSION_ID="18.10"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=cosmic
UBUNTU_CODENAME=cosmic`)

var cosmicOSReleaseBad []byte = []byte(`NAME="Ubuntu"
VERSION="18.10 ( Cuttlefish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.10"
VERSION_ID="18.10"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=
UBUNTU_CODENAME=`)

var cosmicLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.10
DISTRIB_CODENAME=cosmic
DISTRIB_DESCRIPTION="Ubuntu 18.10"`)

var cosmicLSBReleaseBad []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.10
DISTRIB_CODENAME=
DISTRIB_DESCRIPTION="Ubuntu 18.10"`)

// disco test data
var discoOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="19.04 (Disco Dingo)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 19.04"
VERSION_ID="19.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=disco
UBUNTU_CODENAME=disco`)

var discoOSReleaseBad []byte = []byte(`NAME="Ubuntu"
VERSION="19.04 ( Dingo)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 19.04"
VERSION_ID="19.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=
UBUNTU_CODENAME=`)

var discoLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=19.04
DISTRIB_CODENAME=disco
DISTRIB_DESCRIPTION="Ubuntu 19.04"`)

var discoLSBReleaseBad []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=19.04
DISTRIB_CODENAME=
DISTRIB_DESCRIPTION="Ubuntu 19.04"`)

// precise test data
var preciseOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="12.04.5 LTS, Precise Pangolin"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu precise (12.04.5 LTS)"
VERSION_ID="12.04"`)

var preciseOSReleaseBad []byte = []byte(`NAME="Ubuntu"
VERSION="12.04.5 LTS, Pangolin"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu (12.04.5 LTS)"
VERSION_ID="12.04"`)

var preciseLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=12.04
DISTRIB_CODENAME=precise
DISTRIB_DESCRIPTION="Ubuntu 12.04.5 LTS"`)

var preciseLSBReleaseBad []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=12.04
DISTRIB_CODENAME=
DISTRIB_DESCRIPTION="Ubuntu 12.04.5 LTS"`)

// trusty test data
var trustyOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="14.04.6 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.6 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"`)

var trustyOSReleaseBad []byte = []byte(`NAME="Ubuntu"
VERSION="14.04.6 LTS, Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.6 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"`)

var trustyLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.6 LTS"`)

var trustyLSBReleaseBad []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=
DISTRIB_DESCRIPTION="Ubuntu 14.04.6 LTS"`)

// xenial test data
var xenialOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial`)

var xenialOSReleaseBad []byte = []byte(`NAME="Ubuntu"
VERSION="16.04.6 LTS (Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=
UBUNTU_CODENAME=`)

var xenialLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"`)

var xenialLSBReleaseBad []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"`)

func TestUbuntuDistributionScanner(t *testing.T) {
	table := []struct {
		name       string
		release    Release
		osRelease  []byte
		lsbRelease []byte
	}{
		{
			name:       "artful",
			release:    Artful,
			osRelease:  artfulOSRelease,
			lsbRelease: artfulLSBRelease,
		},
		{
			name:       "bionic",
			release:    Bionic,
			osRelease:  bionicOSRelease,
			lsbRelease: bionicLSBRelease,
		},
		{
			name:       "cosmic",
			release:    Cosmic,
			osRelease:  cosmicOSRelease,
			lsbRelease: cosmicLSBRelease,
		},
		{
			name:       "disco",
			release:    Disco,
			osRelease:  discoOSRelease,
			lsbRelease: discoLSBRelease,
		},
		{
			name:       "precise",
			release:    Precise,
			osRelease:  preciseOSRelease,
			lsbRelease: preciseLSBRelease,
		},
		{
			name:       "trusty",
			release:    Trusty,
			osRelease:  trustyOSRelease,
			lsbRelease: trustyLSBRelease,
		},
		{
			name:       "xenial",
			release:    Xenial,
			osRelease:  xenialOSRelease,
			lsbRelease: xenialLSBRelease,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.osRelease))
			if !cmp.Equal(dist, releaseToDist(tt.release)) {
				t.Fatalf("%v", cmp.Diff(dist, releaseToDist(tt.release)))
			}
			dist = scanner.parse(bytes.NewBuffer(tt.lsbRelease))
			if !cmp.Equal(dist, releaseToDist(tt.release)) {
				t.Fatalf("%v", cmp.Diff(dist, releaseToDist(tt.release)))
			}
		})
	}
}

func TestUbuntuDistributionScannerBad(t *testing.T) {
	table := []struct {
		name       string
		release    Release
		osRelease  []byte
		lsbRelease []byte
	}{
		{
			name:       "artful",
			release:    Artful,
			osRelease:  artfulOSReleaseBad,
			lsbRelease: artfulLSBReleaseBad,
		},
		{
			name:       "bionic",
			release:    Bionic,
			osRelease:  bionicOSReleaseBad,
			lsbRelease: bionicLSBReleaseBad,
		},
		{
			name:       "cosmic",
			release:    Cosmic,
			osRelease:  cosmicOSReleaseBad,
			lsbRelease: cosmicLSBReleaseBad,
		},
		{
			name:       "disco",
			release:    Disco,
			osRelease:  discoOSReleaseBad,
			lsbRelease: discoLSBReleaseBad,
		},
		{
			name:       "precise",
			release:    Precise,
			osRelease:  preciseOSReleaseBad,
			lsbRelease: preciseLSBReleaseBad,
		},
		{
			name:       "trusty",
			release:    Trusty,
			osRelease:  trustyOSReleaseBad,
			lsbRelease: trustyLSBReleaseBad,
		},
		{
			name:       "xenial",
			release:    Xenial,
			osRelease:  xenialOSReleaseBad,
			lsbRelease: xenialLSBReleaseBad,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBuffer(tt.osRelease))
			if dist != nil {
				t.Fatalf("expected nil dist got %v", dist)
			}
			dist = scanner.parse(bytes.NewBuffer(tt.lsbRelease))
			if dist != nil {
				t.Fatalf("expected nil dist got %v", dist)
			}
		})
	}
}
