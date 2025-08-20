package osv

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Masterminds/semver"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(&apiStub{t, ""})
	defer srv.Close()
	ctx := zlog.Test(context.Background(), t)

	f := Factory{}
	cfgFunc := func(v any) error {
		cfg := v.(*FactoryConfig)
		cfg.URL = srv.URL
		return nil
	}
	if err := f.Configure(ctx, cfgFunc, srv.Client()); err != nil {
		t.Error(err)
	}

	s, err := f.UpdaterSet(ctx)
	if err != nil {
		t.Error(err)
	}
	if len(s.Updaters()) == 0 {
		t.Errorf("expected more than 0 updaters")
	}

	for _, u := range s.Updaters() {
		rc, fp, err := u.Fetch(ctx, driver.Fingerprint(""))
		if err != nil {
			t.Error(err)
		}
		_ = fp
		if rc != nil {
			rc.Close()
		}

	}
}

type apiStub struct {
	*testing.T
	path string
}

func (a *apiStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Logf("req: %s", r.RequestURI)
	sys := os.DirFS(filepath.Join("testdata", a.path))
	p := r.URL.Path
	switch {
	case p == "/ecosystems.txt":
		out := bufio.NewWriter(w)
		defer out.Flush()
		fmt.Fprintln(out, "testing_ecosystem")
		ms, err := fs.Glob(sys, "*.zip")
		if err != nil {
			panic(err) // can only ever be ErrBadPatern
		}
		for _, m := range ms {
			fmt.Fprintln(out, strings.TrimSuffix(m, ".zip"))
		}
	case strings.HasSuffix(p, "all.zip"):
		w.WriteHeader(http.StatusOK)
		n := strings.ToLower(path.Dir(p)[1:]) + ".zip"
		a.Logf("serving %q", n)
		if f, err := sys.Open(n); errors.Is(err, nil) {
			defer f.Close()
			if _, err := io.Copy(w, f); err != nil {
				a.Error(err)
			}
			return
		}
		z := zip.NewWriter(w)
		if err := z.SetComment("empty zip"); err != nil {
			a.Error(err)
		}
		if err := z.Close(); err != nil {
			a.Error(err)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestParse(t *testing.T) {
	srv := httptest.NewServer(&apiStub{t, ""})
	defer srv.Close()
	ctx := zlog.Test(context.Background(), t)

	f := Factory{}
	cfgFunc := func(v any) error {
		cfg := v.(*FactoryConfig)
		cfg.URL = srv.URL
		return nil
	}
	if err := f.Configure(ctx, cfgFunc, srv.Client()); err != nil {
		t.Error(err)
	}
	s, err := f.UpdaterSet(ctx)
	if err != nil {
		t.Error(err)
	}
	if len(s.Updaters()) == 0 {
		t.Errorf("expected more than 0 updaters")
	}

	for _, u := range s.Updaters() {
		rc, _, err := u.Fetch(ctx, driver.Fingerprint(""))
		if err != nil {
			t.Error(err)
		}
		defer rc.Close()
		vs, err := u.Parse(ctx, rc)
		if err != nil {
			t.Error(err)
		}
		t.Logf("parsed %d vulnerabilities", len(vs))
		if len(vs) != 0 {
			for _, v := range vs {
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetIndent("", "\t")
				if err := enc.Encode(v); err != nil {
					t.Error(err)
				}
				t.Log(buf.String())
			}
		}
	}
}

var insertTestCases = []struct {
	name          string
	ad            *advisory
	expectedVulns []claircore.Vulnerability
}{
	{
		name: "normal",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "SEMVER",
							Events: []rangeEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "0.4.0",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("0.0.0")),
					Upper: claircore.FromSemver(semver.MustParse("0.4.0")),
				},
				FixedInVersion: "0.4.0",
			},
		},
	},
	{
		name: "unfixed",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "SEMVER",
							Events: []rangeEvent{
								{
									Introduced: "0",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("0.0.0")),
					Upper: claircore.Version{
						Kind: "semver",
						V:    [10]int32{65535, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
				FixedInVersion: "",
			},
		},
	},
	{
		name: "two_affected",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "SEMVER",
							Events: []rangeEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "0.4.10",
								},
							},
						},
					},
				},
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "SEMVER",
							Events: []rangeEvent{
								{
									Introduced: "0.5.0",
								},
								{
									Fixed: "0.5.3",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("0.0.0")),
					Upper: claircore.FromSemver(semver.MustParse("0.4.10")),
				},
				FixedInVersion: "0.4.10",
			},
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("0.5.0")),
					Upper: claircore.FromSemver(semver.MustParse("0.5.3")),
				},
				FixedInVersion: "0.5.3",
			},
		},
	},
	{
		name: "three_fixes",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "SEMVER",
							Events: []rangeEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "2.1.16",
								},
								{
									Introduced: "2.2.0",
								},
								{
									Fixed: "2.2.10",
								},
								{
									Introduced: "2.3.0",
								},
								{
									Fixed: "2.3.5",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("0.0.0")),
					Upper: claircore.FromSemver(semver.MustParse("2.1.16")),
				},
				FixedInVersion: "2.1.16",
			},
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("2.2.0")),
					Upper: claircore.FromSemver(semver.MustParse("2.2.10")),
				},
				FixedInVersion: "2.2.10",
			},
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("2.3.0")),
					Upper: claircore.FromSemver(semver.MustParse("2.3.5")),
				},
				FixedInVersion: "2.3.5",
			},
		},
	},
	{
		name: "two_fixes_one_unfixed",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "SEMVER",
							Events: []rangeEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "2.1.16",
								},
								{
									Introduced: "2.2.0",
								},
								{
									Fixed: "2.2.10",
								},
								{
									Introduced: "2.3.0",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("0.0.0")),
					Upper: claircore.FromSemver(semver.MustParse("2.1.16")),
				},
				FixedInVersion: "2.1.16",
			},
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("2.2.0")),
					Upper: claircore.FromSemver(semver.MustParse("2.2.10")),
				},
				FixedInVersion: "2.2.10",
			},
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("2.3.0")),
					Upper: claircore.Version{
						Kind: "semver",
						V:    [10]int32{65535, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
				FixedInVersion: "",
			},
		},
	},
	{
		// In this situation we're just expecting the last one.
		name: "two_consecutive_introduced_invalid",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "SEMVER",
							Events: []rangeEvent{
								{
									Introduced: "2.2.0",
								},
								{
									Introduced: "2.3.0",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:    "test1",
				Updater: "test",
				Range: &claircore.Range{
					Lower: claircore.FromSemver(semver.MustParse("2.3.0")),
					Upper: claircore.Version{
						Kind: "semver",
						V:    [10]int32{65535, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
				FixedInVersion: "",
			},
		},
	},
	{
		name: "ecosystem_multi",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "PyPI",
						Name:      "cherrypy",
					},
					Ranges: []_range{
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "2.1.1",
								},
								{
									Introduced: "3.0",
								},
								{
									Fixed: "3.0.2",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:           "test1",
				Updater:        "test",
				Range:          nil,
				FixedInVersion: "fixed=2.1.1",
			},
			{
				Name:           "test1",
				Updater:        "test",
				Range:          nil,
				FixedInVersion: "fixed=3.0.2&introduced=3.0",
			},
		},
	},
	{
		name: "ecosystem_unfixed",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "PyPI",
						Name:      "cherrypy",
					},
					Ranges: []_range{
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "3.0",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:           "test1",
				Updater:        "test",
				Range:          nil,
				FixedInVersion: "introduced=3.0",
			},
		},
	},
	{
		name: "same package different ranges",
		ad: &advisory{
			ID: "test1",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "Maven",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "0",
								},
								{
									Fixed: "0.4.0",
								},
							},
						},
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "1.0.0",
								},
								{
									Fixed: "1.2.0",
								},
							},
						},
					},
				},
			},
		},
		expectedVulns: []claircore.Vulnerability{
			{
				Name:           "test1",
				Updater:        "test",
				FixedInVersion: "fixed=0.4.0",
			},
			{
				Name:           "test1",
				Updater:        "test",
				FixedInVersion: "fixed=1.2.0&introduced=1.0.0",
			},
		},
	},
}

// cmpIgnore will ignore everything expect the Name, Updater, Range and FixedInVersion.
var cmpIgnore = cmpopts.IgnoreFields(
	claircore.Vulnerability{}, "ID", "Updater", "Description", "Severity", "NormalizedSeverity", "Package", "Repo")

func TestInsert(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	for _, tt := range insertTestCases {
		t.Run(tt.name, func(t *testing.T) {
			ecs := newECS("test")

			err := ecs.Insert(ctx, nil, "", tt.ad)
			if err != nil {
				t.Error("got error Inserting advisory", err)
			}
			if len(ecs.Vulnerability) != len(tt.expectedVulns) {
				t.Fatalf("should have %d vulnerability but got %d", len(tt.expectedVulns), len(ecs.Vulnerability))
			}

			if !cmp.Equal(ecs.Vulnerability, tt.expectedVulns, cmpIgnore) {
				t.Error(cmp.Diff(ecs.Vulnerability, tt.expectedVulns, cmpIgnore))
			}
		})
	}
}

var severityTestCases = []struct {
	name                       string
	a                          *advisory
	expectedNormalizedSeverity claircore.Severity
	expectedSeverity           string
}{
	{
		name: "CVSS V3 HIGH",
		a: &advisory{
			ID: "test1",
			Severity: []severity{
				{
					Type:  "CVSS_V3",
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				},
			},
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "0.1",
									Fixed:      "0.4",
								},
							},
						},
					},
				},
			},
		},
		expectedNormalizedSeverity: claircore.High,
		expectedSeverity:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},
	{
		name: "CVSS V2 MEDIUM",
		a: &advisory{
			ID: "test2",
			Severity: []severity{
				{
					Type:  "CVSS_V2",
					Score: "AV:L/AC:H/Au:N/C:C/I:C/A:C",
				},
			},
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "0.1",
									Fixed:      "0.4",
								},
							},
						},
					},
				},
			},
		},
		expectedNormalizedSeverity: claircore.Medium,
		expectedSeverity:           "AV:L/AC:H/Au:N/C:C/I:C/A:C",
	},
	{
		name: "database_specific moderate",
		a: &advisory{
			ID: "test2",
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "0.1",
									Fixed:      "0.4",
								},
							},
						},
					},
				},
			},
			Database: json.RawMessage([]byte(`{"severity":"moderate"}`)),
		},
		expectedNormalizedSeverity: claircore.Medium,
		expectedSeverity:           "moderate",
	},
	{
		name: "CVSS V3 HIGH and database_specific moderate",
		a: &advisory{
			ID: "test2",
			Severity: []severity{
				{
					Type:  "CVSS_V3",
					Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				},
			},
			Affected: []affected{
				{
					Package: _package{
						Ecosystem: "go",
						Name:      "something",
					},
					Ranges: []_range{
						{
							Type: "ECOSYSTEM",
							Events: []rangeEvent{
								{
									Introduced: "0.1",
									Fixed:      "0.4",
								},
							},
						},
					},
				},
			},
			Database: json.RawMessage([]byte(`{"severity":"moderate"}`)),
		},
		expectedNormalizedSeverity: claircore.High,
		expectedSeverity:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},
}

func TestSeverityParsing(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	for _, tt := range severityTestCases {
		t.Run(tt.name, func(t *testing.T) {
			ecs := newECS("test")

			err := ecs.Insert(ctx, nil, "", tt.a)
			if err != nil {
				t.Error("got error Inserting advisory", err)
			}
			if len(ecs.Vulnerability) != 1 {
				t.Errorf("should have one vulnerability but got %d", len(ecs.Vulnerability))
			}
			v := ecs.Vulnerability[0]
			if v.NormalizedSeverity != tt.expectedNormalizedSeverity {
				t.Errorf("expected severity %q but got %q", tt.expectedNormalizedSeverity, v.NormalizedSeverity)
			}
			if v.Severity != tt.expectedSeverity {
				t.Errorf("expected severity %q but got %q", tt.expectedSeverity, v.Severity)
			}

		})
	}
}

func TestInsertLinksAliases(t *testing.T) {
	tests := []struct {
		name string
		adv  advisory
		want string
	}{
		{
			name: "only refs",
			adv: advisory{
				References: []reference{
					{URL: "https://example.com/ref1"},
					{URL: "https://example.com/ref2"},
				},
				Affected: []affected{{
					Package: _package{Ecosystem: ecosystemGo, Name: "pkg"},
					Ranges:  []_range{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
				}},
			},
			want: "https://example.com/ref1 https://example.com/ref2",
		},
		{
			name: "only aliases single",
			adv: advisory{
				Aliases: []string{"CVE-2023-0001"},
				Affected: []affected{{
					Package: _package{Ecosystem: ecosystemGo, Name: "pkg"},
					Ranges:  []_range{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
				}},
			},
			want: "https://osv.dev/vulnerability/CVE-2023-0001",
		},
		{
			name: "only aliases multiple",
			adv: advisory{
				Aliases: []string{"CVE-2023-0001", "GHSA-xxxx-yyyy"},
				Affected: []affected{{
					Package: _package{Ecosystem: ecosystemGo, Name: "pkg"},
					Ranges:  []_range{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
				}},
			},
			want: "https://osv.dev/vulnerability/CVE-2023-0001 https://osv.dev/vulnerability/GHSA-xxxx-yyyy",
		},
		{
			name: "refs then aliases",
			adv: advisory{
				References: []reference{{URL: "https://example.com/ref1"}, {URL: "https://example.com/ref2"}},
				Aliases:    []string{"CVE-2023-0001", "GHSA-xxxx-yyyy"},
				Affected: []affected{{
					Package: _package{Ecosystem: ecosystemGo, Name: "pkg"},
					Ranges:  []_range{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
				}},
			},
			want: "https://example.com/ref1 https://example.com/ref2 https://osv.dev/vulnerability/CVE-2023-0001 https://osv.dev/vulnerability/GHSA-xxxx-yyyy",
		},
		{
			name: "single ref",
			adv: advisory{
				References: []reference{{URL: "https://example.com/ref1"}},
				Affected: []affected{{
					Package: _package{Ecosystem: ecosystemGo, Name: "pkg"},
					Ranges:  []_range{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
				}},
			},
			want: "https://example.com/ref1",
		},
		{
			name: "empty",
			adv: advisory{
				Affected: []affected{{
					Package: _package{Ecosystem: ecosystemGo, Name: "pkg"},
					Ranges:  []_range{{Type: "SEMVER", Events: []rangeEvent{{Introduced: "0"}}}},
				}},
			},
			want: "",
		},
	}

	ctx := zlog.Test(context.Background(), t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newECS("osv")
			var st stats
			if err := (&e).Insert(ctx, &st, "pkg", &tt.adv); err != nil {
				t.Fatalf("Insert() error: %v", err)
			}
			if len(e.Vulnerability) == 0 {
				t.Fatalf("no vulnerability recorded")
			}
			got := e.Vulnerability[len(e.Vulnerability)-1].Links
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
