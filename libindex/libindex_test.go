package libindex

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"strconv"
	"testing"

	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"

	"github.com/quay/claircore"
	indexer "github.com/quay/claircore/test/mock/indexer"
)

func createTestVulns(n int) []claircore.Vulnerability {
	vulns := []claircore.Vulnerability{}
	for i := 0; i < n; i++ {
		vulns = append(vulns, claircore.Vulnerability{
			ID:                 strconv.Itoa(i),
			Name:               "CVE-2018-20187",
			Links:              "https://security.alpinelinux.org/vuln/CVE-2018-20187",
			Updater:            "alpine-community-v3.10-updater",
			FixedInVersion:     "2.9.0-r0",
			NormalizedSeverity: claircore.Unknown,
			Package: &claircore.Package{
				Name: "botan",
				Kind: claircore.BINARY,
			},
		})
	}
	return vulns
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
	ctx := context.Background()
	tt := []struct {
		name                 string
		inputVulns           []claircore.Vulnerability
		numExpectedVulns     int
		numExpectedManifests int
		err                  bool
		mockStore            func(t *testing.T) indexer.Store
	}{
		{
			name:                 "SimplePath",
			inputVulns:           createTestVulns(2),
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
		{
			name:                 "ManyVulns",
			inputVulns:           createTestVulns(40),
			numExpectedVulns:     40,
			numExpectedManifests: 40,
			mockStore: func(t *testing.T) indexer.Store {
				ctrl := gomock.NewController(t)
				s := indexer.NewMockStore(ctrl)
				s.EXPECT().AffectedManifests(gomock.Any(), gomock.Any()).Return(
					[]claircore.Digest{
						digest("first digest"),
						digest("second digest"),
					},
					nil,
				).MaxTimes(40)
				return s
			},
		},
	}

	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
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

	t.Run("CancelledContext", func(t *testing.T) {
		for _, table := range tt {
			t.Run(table.name, func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				ctx, cancel := context.WithCancelCause(ctx)
				want := errors.New("early cancel")
				cancel(want)
				s := table.mockStore(t)
				li := &Libindex{store: s}

				a, err := li.AffectedManifests(ctx, table.inputVulns)
				if err == nil {
					t.Errorf("did not expect error: %v", err)
				}
				if a != nil {
					t.Errorf("did not expect result: %v", a)
				}
				if !errors.Is(err, want) {
					t.Errorf("got: %v, want: %v", err, want)
				}
			})
		}
	})
}

func BenchmarkAffectedManifests(b *testing.B) {
	ctx := context.Background()
	// create store
	ctrl := gomock.NewController(b)
	s := indexer.NewMockStore(ctrl)
	s.EXPECT().AffectedManifests(gomock.Any(), gomock.Any()).Return(
		[]claircore.Digest{
			digest("first digest"),
			digest("second digest"),
		},
		nil,
	).MaxTimes(100 * b.N)

	ctx = zlog.Test(ctx, b)
	li := &Libindex{store: s}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, err := li.AffectedManifests(ctx, createTestVulns(100))
		if err != nil {
			b.Fatalf("did not expect error: %v", err)
		}
	}
}
