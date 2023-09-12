package rhcc

import (
	"context"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestDB(t *testing.T) {
	t.Parallel()
	cve20213762issued, _ := time.Parse(time.RFC3339, "2021-09-28T00:00:00Z")

	date_2021_12_14, _ := time.Parse(time.RFC3339, "2021-12-14T00:00:00Z")
	date_2021_12_16, _ := time.Parse(time.RFC3339, "2021-12-16T00:00:00Z")
	date_2021_05_19, _ := time.Parse(time.RFC3339, "2021-05-19T00:00:00Z")
	date_2021_08_03, _ := time.Parse(time.RFC3339, "2021-08-03T00:00:00Z")

	tt := []dbTestcase{
		{
			Name: "Clair",
			File: "testdata/cve-2021-3762.xml",
			Want: []*claircore.Vulnerability{
				{
					Name:               "RHSA-2021:3665",
					Description:        "A directory traversal vulnerability was found in the ClairCore engine of Clair. An attacker can exploit this by supplying a crafted container image which, when scanned by Clair, allows for arbitrary file write on the filesystem, potentially allowing for remote code execution.",
					Package:            &claircore.Package{Name: "quay/clair-rhel8", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             cve20213762issued,
					Severity:           "Important",
					Links:              "https://access.redhat.com/errata/RHSA-2021:3665 https://access.redhat.com/security/cve/CVE-2021-3762",
					NormalizedSeverity: claircore.High,
					FixedInVersion:     "v3.5.7-8",
					Repo:               &goldRepo,
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V: [10]int32{
								3,
								5,
								math.MaxInt32,
							},
						},
					},
				},
			},
		},
		{
			Name: "Hive",
			File: "testdata/cve-2021-44228-ose-metering-hive.xml",
			Want: []*claircore.Vulnerability{
				{
					Name:               "RHSA-2021:5106",
					Description:        "A flaw was found in the Apache Log4j logging library in versions from 2.0.0 and before 2.15.0. A remote attacker who can control log messages or log message parameters, can execute arbitrary code on the server via JNDI LDAP endpoint.",
					Package:            &claircore.Package{Name: "openshift4/ose-metering-hive", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             date_2021_12_16,
					Severity:           "Moderate",
					Links:              "https://access.redhat.com/errata/RHSA-2021:5106 https://access.redhat.com/security/cve/CVE-2021-44228",
					NormalizedSeverity: claircore.Medium,
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 6, math.MaxInt32},
						},
					},
					FixedInVersion: "v4.6.0-202112140546.p0.g8b9da97.assembly.stream",
					Repo:           &goldRepo,
				},
				{
					Name:               "RHSA-2021:5107",
					Description:        "A flaw was found in the Apache Log4j logging library in versions from 2.0.0 and before 2.15.0. A remote attacker who can control log messages or log message parameters, can execute arbitrary code on the server via JNDI LDAP endpoint.",
					Package:            &claircore.Package{Name: "openshift4/ose-metering-hive", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             date_2021_12_16,
					Severity:           "Critical",
					Links:              "https://access.redhat.com/errata/RHSA-2021:5107 https://access.redhat.com/security/cve/CVE-2021-44228",
					NormalizedSeverity: claircore.Critical,
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 7},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 7, math.MaxInt32},
						},
					},
					FixedInVersion: "v4.7.0-202112140553.p0.g091bb99.assembly.stream",
					Repo:           &goldRepo,
				},
				{
					Name:               "RHSA-2021:5108",
					Description:        "A flaw was found in the Apache Log4j logging library in versions from 2.0.0 and before 2.15.0. A remote attacker who can control log messages or log message parameters, can execute arbitrary code on the server via JNDI LDAP endpoint.",
					Package:            &claircore.Package{Name: "openshift4/ose-metering-hive", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             date_2021_12_14,
					Severity:           "Critical",
					Links:              "https://access.redhat.com/errata/RHSA-2021:5108 https://access.redhat.com/security/cve/CVE-2021-44228",
					NormalizedSeverity: claircore.Critical,
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 8},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 8, math.MaxInt32},
						},
					},
					FixedInVersion: "v4.8.0-202112132154.p0.g57dd03a.assembly.stream",
					Repo:           &goldRepo,
				},
			},
		},
		{
			Name: "Logging",
			File: "testdata/cve-2021-44228-openshift-logging.xml",
			Want: []*claircore.Vulnerability{
				{
					Name:               "RHSA-2021:5129",
					Description:        "A flaw was found in the Apache Log4j logging library in versions from 2.0.0 and before 2.15.0. A remote attacker who can control log messages or log message parameters, can execute arbitrary code on the server via JNDI LDAP endpoint.",
					Package:            &claircore.Package{Name: "openshift-logging/elasticsearch6-rhel8", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             date_2021_12_14,
					Severity:           "Critical",
					NormalizedSeverity: claircore.Critical,
					Links:              "https://access.redhat.com/errata/RHSA-2021:5129 https://access.redhat.com/security/cve/CVE-2021-44228",
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{6, 8},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{6, 8, math.MaxInt32},
						},
					},
					FixedInVersion: "v6.8.1-65",
					Repo:           &goldRepo,
				},
				{
					Name:               "RHSA-2021:5137",
					Description:        "A flaw was found in the Apache Log4j logging library in versions from 2.0.0 and before 2.15.0. A remote attacker who can control log messages or log message parameters, can execute arbitrary code on the server via JNDI LDAP endpoint.",
					Package:            &claircore.Package{Name: "openshift-logging/elasticsearch6-rhel8", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             date_2021_12_14,
					Severity:           "Moderate",
					Links:              "https://access.redhat.com/errata/RHSA-2021:5137 https://access.redhat.com/security/cve/CVE-2021-44228",
					NormalizedSeverity: claircore.Medium,
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{5, 0, math.MaxInt32},
						},
					},
					FixedInVersion: "v5.0.10-1",
					Repo:           &goldRepo,
				},
			},
		},
		{
			Name: "Kubernetes",
			File: "testdata/cve-2020-8565.xml",
			Want: []*claircore.Vulnerability{
				{
					Name:               "RHBA-2021:3003",
					Description:        "A flaw was found in kubernetes. In Kubernetes, if the logging level is to at least 9, authorization and bearer tokens will be written to log files. This can occur both in API server logs and client tool output like `kubectl`. Previously, CVE-2019-11250 was assigned for the same issue for logging levels of at least 4.",
					Package:            &claircore.Package{Name: "ocs4/rook-ceph-rhel8-operator", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             date_2021_08_03,
					Severity:           "Moderate",
					NormalizedSeverity: claircore.Medium,
					Links:              "https://access.redhat.com/errata/RHBA-2021:3003 https://access.redhat.com/security/cve/CVE-2020-8565",
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 8},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 8, math.MaxInt32},
						},
					},
					FixedInVersion: "4.8-167.9a9db5f.release_4.8",
					Repo:           &goldRepo,
				},
				{
					Name:               "RHSA-2021:2041",
					Description:        "A flaw was found in kubernetes. In Kubernetes, if the logging level is to at least 9, authorization and bearer tokens will be written to log files. This can occur both in API server logs and client tool output like `kubectl`. Previously, CVE-2019-11250 was assigned for the same issue for logging levels of at least 4.",
					Package:            &claircore.Package{Name: "ocs4/rook-ceph-rhel8-operator", Kind: claircore.BINARY},
					Updater:            "rhel-container-updater",
					Issued:             date_2021_05_19,
					Severity:           "Moderate",
					Links:              "https://access.redhat.com/errata/RHSA-2021:2041 https://access.redhat.com/security/cve/CVE-2020-8565",
					NormalizedSeverity: claircore.Medium,
					Range: &claircore.Range{
						Lower: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{},
						},
						Upper: claircore.Version{
							Kind: "rhctag",
							V:    [10]int32{4, 7, math.MaxInt32},
						},
					},
					FixedInVersion: "4.7-140.49a6fcf.release_4.7",
					Repo:           &goldRepo,
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}

type dbTestcase struct {
	Name string
	File string
	Want []*claircore.Vulnerability
}

func cpeUnbind(cpeValue string) cpe.WFN {
	wfn, _ := cpe.Unbind(cpeValue)
	return wfn
}

func (tc dbTestcase) Run(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	f, err := os.Open(tc.File)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	u := &updater{}
	got, err := u.Parse(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found %d vulnerabilities", len(got))
	if len(got) != len(tc.Want) {
		t.Fatalf("got: %d vulnerabilities, want %d vulnerabilities", len(got), len(tc.Want))
	}
	// Sort for the comparison, because the Vulnerabilities method can return
	// the slice in any order.
	sort.SliceStable(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	if !cmp.Equal(tc.Want, got) {
		t.Error(cmp.Diff(tc.Want, got))
	}
}
