package ubuntu

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
)

// impish test data
var impishOSRelease []byte = []byte(`PRETTY_NAME="Ubuntu 21.10"
NAME="Ubuntu"
VERSION_ID="21.10"
VERSION="21.10 (Impish Indri)"
VERSION_CODENAME=impish
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=impish`)

var impishLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=21.10
DISTRIB_CODENAME=impish
DISTRIB_DESCRIPTION="Ubuntu 21.10"`)

// eoan test data
var eoanOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="19.10 (Eoan Ermine)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 19.10"
VERSION_ID="19.10"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=eoan
UBUNTU_CODENAME=eoan`)

var eoanLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=19.10
DISTRIB_CODENAME=eoan
DISTRIB_DESCRIPTION="Ubuntu 19.10"`)

// focal test data
var focalOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="20.04 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal`)

var focalLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04 LTS"`)

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

var artfulLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=17.10
DISTRIB_CODENAME=artful
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

var bionicLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
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

var cosmicLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.10
DISTRIB_CODENAME=cosmic
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

var discoLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=19.04
DISTRIB_CODENAME=disco
DISTRIB_DESCRIPTION="Ubuntu 19.04"`)

// precise test data
var preciseOSRelease []byte = []byte(`NAME="Ubuntu"
VERSION="12.04.5 LTS, Precise Pangolin"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu precise (12.04.5 LTS)"
VERSION_ID="12.04"`)

var preciseLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=12.04
DISTRIB_CODENAME=precise
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

var trustyLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
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

var xenialLSBRelease []byte = []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		Name string
		Want claircore.Distribution
	}{
		{
			Name: "10.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "10.04",
				PrettyName:      "Ubuntu 10.04",
				VersionCodeName: "lucid",
				Version:         "10.04 (Lucid)",
			},
		},
		{
			Name: "12.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "12.04",
				PrettyName:      "Ubuntu 12.04",
				VersionCodeName: "precise",
				Version:         "12.04 (Precise)",
			},
		},
		{
			Name: "12.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "12.10",
				PrettyName:      "Ubuntu 12.10",
				VersionCodeName: "quantal",
				Version:         "12.10 (Quantal)",
			},
		},
		{
			Name: "13.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "13.04",
				PrettyName:      "Ubuntu 13.04",
				VersionCodeName: "raring",
				Version:         "13.04 (Raring)",
			},
		},
		{
			Name: "13.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "13.10",
				PrettyName:      "Ubuntu 13.10",
				VersionCodeName: "saucy",
				Version:         "13.10 (Saucy)",
			},
		},
		{
			Name: "14.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "14.04",
				PrettyName:      "Ubuntu 14.04",
				VersionCodeName: "trusty",
				Version:         "14.04 (Trusty)",
			},
		},
		{
			Name: "14.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "14.10",
				PrettyName:      "Ubuntu 14.10",
				VersionCodeName: "utopic",
				Version:         "14.10 (Utopic)",
			},
		},
		{
			Name: "15.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "15.04",
				PrettyName:      "Ubuntu 15.04",
				VersionCodeName: "vivid",
				Version:         "15.04 (Vivid)",
			},
		},
		{
			Name: "15.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "15.10",
				PrettyName:      "Ubuntu 15.10",
				VersionCodeName: "wily",
				Version:         "15.10 (Wily)",
			},
		},
		{
			Name: "16.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "16.04",
				PrettyName:      "Ubuntu 16.04",
				VersionCodeName: "xenial",
				Version:         "16.04 (Xenial)",
			},
		},
		{
			Name: "16.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "16.10",
				PrettyName:      "Ubuntu 16.10",
				VersionCodeName: "yakkety",
				Version:         "16.10 (Yakkety)",
			},
		},
		{
			Name: "17.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "17.04",
				PrettyName:      "Ubuntu 17.04",
				VersionCodeName: "zesty",
				Version:         "17.04 (Zesty)",
			},
		},
		{
			Name: "17.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "17.10",
				PrettyName:      "Ubuntu 17.10",
				VersionCodeName: "artful",
				Version:         "17.10 (Artful)",
			},
		},
		{
			Name: "18.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "18.04",
				PrettyName:      "Ubuntu 18.04",
				VersionCodeName: "bionic",
				Version:         "18.04 (Bionic)",
			},
		},
		{
			Name: "18.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "18.10",
				PrettyName:      "Ubuntu 18.10",
				VersionCodeName: "cosmic",
				Version:         "18.10 (Cosmic)",
			},
		},
		{
			Name: "19.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "19.04",
				PrettyName:      "Ubuntu 19.04",
				VersionCodeName: "disco",
				Version:         "19.04 (Disco)",
			},
		},
		{
			Name: "19.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "19.10",
				PrettyName:      "Ubuntu 19.10",
				VersionCodeName: "eoan",
				Version:         "19.10 (Eoan)",
			},
		},
		{
			Name: "20.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "20.04",
				PrettyName:      "Ubuntu 20.04",
				VersionCodeName: "focal",
				Version:         "20.04 (Focal)",
			},
		},
		{
			Name: "20.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "20.10",
				PrettyName:      "Ubuntu 20.10",
				VersionCodeName: "groovy",
				Version:         "20.10 (Groovy)",
			},
		},
		{
			Name: "21.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "21.04",
				PrettyName:      "Ubuntu 21.04",
				VersionCodeName: "hirsute",
				Version:         "21.04 (Hirsute)",
			},
		},
		{
			Name: "21.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "21.10",
				PrettyName:      "Ubuntu 21.10",
				VersionCodeName: "impish",
				Version:         "21.10 (Impish)",
			},
		},
		{
			Name: "22.04",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "22.04",
				PrettyName:      "Ubuntu 22.04",
				VersionCodeName: "jammy",
				Version:         "22.04 (Jammy)",
			},
		},
		{
			Name: "22.10",
			Want: claircore.Distribution{
				Name:            "Ubuntu",
				DID:             "ubuntu",
				VersionID:       "22.10",
				PrettyName:      "Ubuntu 22.10",
				VersionCodeName: "kinetic",
				Version:         "22.10 (Kinetic)",
			},
		},
	}
	todo := make(map[string]struct{})
	ents, err := os.ReadDir("testdata/dist")
	if err != nil {
		t.Error(err)
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		todo[e.Name()] = struct{}{}
	}
	for _, tc := range table {
		t.Run(tc.Name, func(t *testing.T) {
			sys := os.DirFS(filepath.Join("testdata", "dist", tc.Name))
			got, err := findDist(sys)
			if err != nil {
				t.Fatal(err)
			}
			if want := &tc.Want; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
		delete(todo, tc.Name)
	}
	if len(todo) != 0 {
		t.Errorf("missed directories: %v", todo)
	}
}
