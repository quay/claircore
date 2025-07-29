package rhel

import (
	"context"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

type vulnerableTestCase struct {
	ir   *claircore.IndexRecord
	v    *claircore.Vulnerability
	name string
	want bool
}

func TestVulnerable(t *testing.T) {
	t.Parallel()

	record := &claircore.IndexRecord{
		Package: &claircore.Package{
			Version: "0.33.0-6.el8",
		},
		Repository: &claircore.Repository{
			CPE:  cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8::baseos"),
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	openshiftRecord := &claircore.IndexRecord{
		Package: &claircore.Package{
			Version: "0.33.0-6.el8",
		},
		Repository: &claircore.Repository{
			CPE:  cpe.MustUnbind("cpe:/a:redhat:openshift:4.13::el8"),
			Name: "cpe:/a:redhat:openshift:4.13::el8",
			Key:  "rhel-cpe-repository",
		},
	}
	openshift5Record := &claircore.IndexRecord{
		Package: &claircore.Package{
			Version: "0.33.0-6.el8",
		},
		Repository: &claircore.Repository{
			CPE:  cpe.MustUnbind("cpe:/a:redhat:openshift:5.1::el8"),
			Name: "cpe:/a:redhat:openshift:5.1::el8",
			Key:  "rhel-cpe-repository",
		},
	}
	fixedVulnPast := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-5.el8",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	fixedVulnCurrent := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-6.el8",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	fixedVulnFuture := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "0.33.0-7.el8",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVuln := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnBadCPE := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cep:o:redhat:enterprise_linux:8::baseos",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnRepoIsSubset := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnRepoNotSubset := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/o:redhat:enterprise_linux:8::appstream",
			Key:  "rhel-cpe-repository",
		},
	}
	unfixedVulnRepoSubstring := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/a:redhat:openshift:4",
			Key:  "rhel-cpe-repository",
		},
	}
	genericWilcardRepo := &claircore.Vulnerability{
		Package: &claircore.Package{
			Version: "",
		},
		FixedInVersion: "",
		Repo: &claircore.Repository{
			Name: "cpe:/a:redhat:openshift:4.%02::el8",
			Key:  "rhel-cpe-repository",
		},
	}

	testCases := []vulnerableTestCase{
		{ir: record, v: fixedVulnPast, want: false, name: "vuln fixed in past version"},
		{ir: record, v: fixedVulnCurrent, want: false, name: "vuln fixed in current version"},
		{ir: record, v: fixedVulnFuture, want: true, name: "outdated package"},
		{ir: record, v: unfixedVuln, want: true, name: "unfixed vuln"},
		{ir: record, v: unfixedVulnBadCPE, want: false, name: "unfixed vuln, invalid CPE"},
		{ir: record, v: unfixedVulnRepoIsSubset, want: true, name: "unfixed vuln, Repo is a subset"},
		{ir: record, v: unfixedVulnRepoNotSubset, want: false, name: "unfixed vuln, Repo not a subset"},
		{ir: openshiftRecord, v: unfixedVulnRepoSubstring, want: true, name: "unfixed vuln, Repo is a substring match"},
		{ir: openshiftRecord, v: genericWilcardRepo, want: true, name: "unfixed vuln, Repo is a superset (with wildcard)"},
		{ir: openshift5Record, v: genericWilcardRepo, want: false, name: "unfixed vuln, Repo isn't a superset (with wildcard)"},
	}

	m := &Matcher{}
	ctx := context.Background()
	ctx = zlog.Test(ctx, t)
	for _, tc := range testCases {
		got, err := m.Vulnerable(ctx, tc.ir, tc.v)
		if err != nil {
			t.Error(err)
		}
		if tc.want != got {
			t.Errorf("%q failed: want %t, got %t", tc.name, tc.want, got)
		}
	}
}

func TestIsCPEStringSubsetMatch(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name               string
		recordCPE, vulnCPE cpe.WFN
		match              bool
	}{
		{
			name:      "Simple",
			recordCPE: cpe.MustUnbind("cpe:/a:redhat:openshift:4.13::el8"),
			vulnCPE:   cpe.MustUnbind("cpe:/a:redhat:openshift:4"),
			match:     true,
		},
		{
			name:      "WrongMinor",
			recordCPE: cpe.MustUnbind("cpe:/a:redhat:openshift:4.13::el8"),
			vulnCPE:   cpe.MustUnbind("cpe:/a:redhat:openshift:4.1::el8"),
			match:     false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tt := tc
			matched := IsCPESubstringMatch(tt.recordCPE, tt.vulnCPE)
			if matched != tt.match {
				t.Errorf("unexpected matching %s and %s", tt.recordCPE, tt.vulnCPE)
			}
		})
	}
}
