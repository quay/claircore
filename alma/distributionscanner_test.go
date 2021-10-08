package alma

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
)

func TestOSReleaseParser(t *testing.T) {
	table := []struct {
		name          string
		osRelease     []byte
		expectedMap   map[string]string
		expectedError error
	}{
		{
			name:      "alma8",
			osRelease: almalinux8OSRelease,
			expectedMap: map[string]string{
				"NAME":                               "AlmaLinux",
				"VERSION":                            "8.4 (Electric Cheetah)",
				"ID":                                 "almalinux",
				"VERSION_ID":                         "8.4",
				"PLATFORM_ID":                        "platform:el8",
				"PRETTY_NAME":                        "AlmaLinux 8.4 (Electric Cheetah)",
				"ANSI_COLOR":                         "0;34",
				"CPE_NAME":                           "cpe:/o:almalinux:almalinux:8.4:GA",
				"HOME_URL":                           "https://almalinux.org/",
				"DOCUMENTATION_URL":                  "https://wiki.almalinux.org/",
				"BUG_REPORT_URL":                     "https://bugs.almalinux.org/",
				"ALMALINUX_MANTISBT_PROJECT":         "AlmaLinux-8",
				"ALMALINUX_MANTISBT_PROJECT_VERSION": "8.4",
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			osReleaseBuff := bytes.NewBuffer(tt.osRelease)
			osReleaseMap, err := parseOSRelease(osReleaseBuff)
			if !cmp.Equal(tt.expectedError, err) {
				t.Fatalf("expecting %v but got %v", tt.expectedError, err)
			}
			if !cmp.Equal(tt.expectedMap, osReleaseMap) {
				t.Fatalf("%v", cmp.Diff(tt.expectedMap, osReleaseMap))
			}
		})
	}
}

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name          string
		dist          *claircore.Distribution
		osRelease     []byte
		expectedError error
	}{
		{
			name:      "almalinux 8",
			osRelease: almalinux8OSRelease,
			dist: &claircore.Distribution{
				ID:              "8",
				DID:             "almalinux",
				Name:            "AlmaLinux",
				Version:         "8.4 (Electric Cheetah)",
				VersionID:       "8.4",
				VersionCodeName: "",
				Arch:            "",
				CPE:             cpe.MustUnbind("cpe:/o:almalinux:almalinux:8.4:GA"),
				PrettyName:      "AlmaLinux 8.4 (Electric Cheetah)",
			},
			expectedError: nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			scanner := DistributionScanner{}
			dist, err := scanner.parse(bytes.NewBuffer(tt.osRelease))
			if !cmp.Equal(err, tt.expectedError) {
				t.Fatalf("expecting %v but got %v", tt.expectedError, err)
			}

			if !cmp.Equal(dist, tt.dist) {
				t.Fatalf("%v", cmp.Diff(dist, tt.dist))
			}
		})
	}
}

var almalinux8OSRelease []byte = []byte(`NAME="AlmaLinux"
VERSION="8.4 (Electric Cheetah)"
ID="almalinux"
VERSION_ID="8.4"
PLATFORM_ID="platform:el8"
PRETTY_NAME="AlmaLinux 8.4 (Electric Cheetah)"
ANSI_COLOR="0;34"
CPE_NAME="cpe:/o:almalinux:almalinux:8.4:GA"
HOME_URL="https://almalinux.org/"
DOCUMENTATION_URL="https://wiki.almalinux.org/"
BUG_REPORT_URL="https://bugs.almalinux.org/"

ALMALINUX_MANTISBT_PROJECT="AlmaLinux-8"
ALMALINUX_MANTISBT_PROJECT_VERSION="8.4"
`)
