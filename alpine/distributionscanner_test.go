package alpine

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type distTestcase struct {
	Release
	OSRelease string
	Issue     string
}

func TestDistributionScanner(t *testing.T) {
	table := []distTestcase{
		{
			Release:   V3_3,
			OSRelease: v3_3_OSRelease,
			Issue:     v3_3_Issue,
		},
		{
			Release:   V3_4,
			OSRelease: v3_4_OSRelease,
			Issue:     v3_4_Issue,
		},
		{
			Release:   V3_5,
			OSRelease: v3_5_OSRelease,
			Issue:     v3_5_Issue,
		},
		{
			Release:   V3_6,
			OSRelease: v3_6_OSRelease,
			Issue:     v3_6_Issue,
		},
		{
			Release:   V3_7,
			OSRelease: v3_7_OSRelease,
			Issue:     v3_7_Issue,
		},
		{
			Release:   V3_8,
			OSRelease: v3_8_OSRelease,
			Issue:     v3_8_Issue,
		},
		{
			Release:   V3_9,
			OSRelease: v3_9_OSRelease,
			Issue:     v3_9_Issue,
		},
		{
			Release:   V3_10,
			OSRelease: v3_10_OSRelease,
			Issue:     v3_10_Issue,
		},
		{
			Release:   V3_11,
			OSRelease: v3_11_OSRelease,
			Issue:     v3_11_Issue,
		},
		{
			Release:   V3_12,
			OSRelease: v3_12_OSRelease,
			Issue:     v3_12_Issue,
		},
	}
	for _, tt := range table {
		t.Run(string(tt.Release), func(t *testing.T) {
			scanner := DistributionScanner{}
			dist := scanner.parse(bytes.NewBufferString(tt.OSRelease))
			if got, want := dist, releaseToDist(tt.Release); !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
			dist = scanner.parse(bytes.NewBufferString(tt.Issue))
			if got, want := dist, releaseToDist(tt.Release); !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

// These are a mess of constants copied out of alpine containers.
//
// Might make sense to move these into testdata files at some point.
const (
	v3_3_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.3.3
PRETTY_NAME="Alpine Linux v3.3"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`
	v3_3_Issue = `Welcome to Alpine Linux 3.3
Kernel \r on an \m (\l)`
	v3_4_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.4.6
PRETTY_NAME="Alpine Linux v3.4"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`
	v3_4_Issue = `Welcome to Alpine Linux 3.4
Kernel \r on an \m (\l)`
	v3_5_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.5.3
PRETTY_NAME="Alpine Linux v3.5"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`
	v3_5_Issue = `Welcome to Alpine Linux 3.5
Kernel \r on an \m (\l)`
	v3_6_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.6.5
PRETTY_NAME="Alpine Linux v3.6"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`
	v3_6_Issue = `Welcome to Alpine Linux 3.6
Kernel \r on an \m (\l)`
	v3_7_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.7.3
PRETTY_NAME="Alpine Linux v3.7"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`
	v3_7_Issue = `Welcome to Alpine Linux 3.7
Kernel \r on an \m (\l)`
	v3_8_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.8.4
PRETTY_NAME="Alpine Linux v3.8"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`
	v3_8_Issue = `Welcome to Alpine Linux 3.8
Kernel \r on an \m (\l)`
	v3_9_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.9.4
PRETTY_NAME="Alpine Linux v3.9"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"`
	v3_9_Issue = `Welcome to Alpine Linux 3.9
Kernel \r on an \m (\l)`
	v3_10_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.10.3
PRETTY_NAME="Alpine Linux v3.10"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"`
	v3_10_Issue = `Welcome to Alpine Linux 3.10
Kernel \r on an \m (\l)`
	v3_11_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.11.6
PRETTY_NAME="Alpine Linux v3.11"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"`
	v3_11_Issue = `Welcome to Alpine Linux 3.11
Kernel \r on an \m (\l)`
	v3_12_OSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.12.1
PRETTY_NAME="Alpine Linux v3.12"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"`
	v3_12_Issue = `Welcome to Alpine Linux 3.12
Kernel \r on an \m (\l)`
)
