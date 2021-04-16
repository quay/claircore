package libindex

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/zlog"
)

var testVulns = []claircore.Vulnerability{
	{
		ID:                 "123",
		Name:               "CVE-2018-20187",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20187",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.9.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.BINARY,
		},
	},
	{
		ID:                 "456",
		Name:               "CVE-2018-12435",
		Links:              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12435",
		Updater:            "alpine-community-v3.10-updater",
		FixedInVersion:     "2.7.0-r0",
		NormalizedSeverity: claircore.Unknown,
		Package: &claircore.Package{
			Name: "botan",
			Kind: claircore.BINARY,
		},
	},
}

func digest(inp string) claircore.Digest {
	h := sha256.New()
	io.WriteString(h, inp)
	d, err := claircore.NewDigest("sha256", h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return d
}

func TestAffectedManifests(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	var tt = []struct {
		name                 string
		inputVulns           []claircore.Vulnerability
		numExpectedVulns     int
		numExpectedManifests int
		err                  bool
		mockStore            func(t *testing.T) indexer.Store
	}{
		{
			name:                 "Simple path",
			inputVulns:           testVulns,
			numExpectedVulns:     2,
			numExpectedManifests: 2,
			mockStore: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				s := indexer.NewMockStore(ctrl)
				s.EXPECT().AffectedManifests(gomock.Any(), gomock.Any()).Return(
					[]claircore.Digest{
						digest("first digest"),
						digest("second digest"),
					},
					nil,
				).MaxTimes(2)
				return s
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx, done := context.WithCancel(ctx)
			defer done()
			ctx = zlog.Test(ctx, t)
			s := table.mockStore(t)
			li := &Libindex{store: s}

			affected, err := li.AffectedManifests(ctx, table.inputVulns)
			if (err == nil) == table.err {
				t.Fatalf("did not expect error: %v", err)
			}

			if table.numExpectedVulns != len(affected.Vulnerabilities) {
				t.Fatalf("got: %d vulnerabilities, want: %d", len(affected.Vulnerabilities), table.numExpectedVulns)
			}
			if table.numExpectedManifests != len(affected.Vulnerabilities) {
				t.Fatalf("got: %d vulnerabilities, want: %d", len(affected.Vulnerabilities), table.numExpectedManifests)
			}
		})
	}
}
