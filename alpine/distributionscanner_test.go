package alpine

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var v3_3_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.3.3
PRETTY_NAME="Alpine Linux v3.3"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`)

var v3_3_Issue []byte = []byte(`Welcome to Alpine Linux 3.3
Kernel \r on an \m (\l)`)

var v3_4_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.4.6
PRETTY_NAME="Alpine Linux v3.4"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`)

var v3_4_Issue []byte = []byte(`Welcome to Alpine Linux 3.4
Kernel \r on an \m (\l)`)

var v3_5_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.5.3
PRETTY_NAME="Alpine Linux v3.5"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`)

var v3_5_Issue []byte = []byte(`Welcome to Alpine Linux 3.5
Kernel \r on an \m (\l)`)

var v3_6_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.6.5
PRETTY_NAME="Alpine Linux v3.6"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`)

var v3_6_Issue []byte = []byte(`Welcome to Alpine Linux 3.6
Kernel \r on an \m (\l)`)

var v3_7_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.7.3
PRETTY_NAME="Alpine Linux v3.7"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`)

var v3_7_Issue []byte = []byte(`Welcome to Alpine Linux 3.7
Kernel \r on an \m (\l)`)

var v3_8_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.8.4
PRETTY_NAME="Alpine Linux v3.8"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`)

var v3_8_Issue []byte = []byte(`Welcome to Alpine Linux 3.8
Kernel \r on an \m (\l)`)

var v3_9_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.9.4
PRETTY_NAME="Alpine Linux v3.9"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"`)

var v3_9_Issue []byte = []byte(`Welcome to Alpine Linux 3.9
Kernel \r on an \m (\l)`)

var v3_10_OSRelease []byte = []byte(`NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.10.3
PRETTY_NAME="Alpine Linux v3.10"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"`)

var v3_10_Issue []byte = []byte(`Welcome to Alpine Linux 3.10
Kernel \r on an \m (\l)`)

func TestDistributionScanner(t *testing.T) {
	table := []struct {
		name      string
		release   Release
		osRelease []byte
		issue     []byte
	}{
		{
			name:      "v3_3",
			release:   V3_3,
			osRelease: v3_3_OSRelease,
			issue:     v3_3_Issue,
		},
		{
			name:      "v3_4",
			release:   V3_4,
			osRelease: v3_4_OSRelease,
			issue:     v3_4_Issue,
		},
		{
			name:      "v3_5",
			release:   V3_5,
			osRelease: v3_5_OSRelease,
			issue:     v3_5_Issue,
		},
		{
			name:      "v3_6",
			release:   V3_6,
			osRelease: v3_6_OSRelease,
			issue:     v3_6_Issue,
		},
		{
			name:      "v3_7",
			release:   V3_7,
			osRelease: v3_7_OSRelease,
			issue:     v3_7_Issue,
		},
		{
			name:      "v3_8",
			release:   V3_8,
			osRelease: v3_8_OSRelease,
			issue:     v3_8_Issue,
		},
		{
			name:      "v3_9",
			release:   V3_9,
			osRelease: v3_9_OSRelease,
			issue:     v3_9_Issue,
		},
		{
			name:      "v3_10",
			release:   V3_10,
			osRelease: v3_10_OSRelease,
			issue:     v3_10_Issue,
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
