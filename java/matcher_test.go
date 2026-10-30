package java

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/claircore/toolkit/types"
)

func TestVulnerable(t *testing.T) {
	matcher := &Matcher{}

	testcases := []struct {
		record *claircore.IndexRecord
		vuln   *claircore.Vulnerability
		name   string
		want   bool
	}{
		{
			name: "pkg0",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.2.9",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "fixed=3.3.0&introduced=3.2.0",
			},
			want: true,
		},
		{
			name: "pkg1",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.3.0",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "fixed=3.3.0&introduced=3.2.0",
			},
			want: false,
		},
		{
			name: "pkg2",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.jfinal:jfinal",
					Version: "4.9.0",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2c25-xfpq-8n9r",
				Description: "Cross-site scripting in ¡final",
				Package: &claircore.Package{
					Name:           "com.jfinal:jfinal",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "fixed=4.9.11",
			},
			want: true,
		},
		{
			name: "pkg3",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.gitblit:gitblit",
					Version: "1.9.3",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-265-ra62-fahg",
				Description: "Path traversal in Gitblit",
				Package: &claircore.Package{
					Name:           "com.gitblit:gitblit",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=1.9.3",
			},
			want: true,
		},
		{
			name: "pkg4",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.gitblit:gitblit",
					Version: "1.9.4",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-265-ra62-fahg",
				Description: "Path traversal in Gitblit",
				Package: &claircore.Package{
					Name:           "com.gitblit:gitblit",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=1.9.3",
			},
			want: false,
		},
		{
			name: "pkg5",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.3.0",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=3.3.0&introduced=3.2.0",
			},
			want: true,
		},
		{
			name: "pkg6",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.openmeetings:openmeetings-parent",
					Version: "3.1.9",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-2965-xxg6-3qh5",
				Description: "Apache OpenMeetings vulnerable to parameter manipulation attacks",
				Package: &claircore.Package{
					Name:           "org.apache.openmeetings:openmeetings-parent",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "lastAffected=3.3.0&introduced=3.2.0",
			},
			want: false,
		},
		{
			name: "pkg7",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "org.apache.tiles:tiles-core",
					Version: "3.0.7",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-qw4h-3xjj-84cc",
				Description: "Go look it up: https://osv.dev/vulnerability/GHSA-qw4h-3xjj-84cc",
				Package: &claircore.Package{
					Name:           "org.apache.tiles:tiles-core",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=2.0.0",
			},
			want: true,
		},
		// The following cases cover CVE-2025-59250 / GHSA-m494-w24q-6f7w
		// (com.microsoft.sqlserver:mssql-jdbc). Microsoft publishes separate
		// Maven coordinates per JDK-target classifier (.jre8/.jre11/.jre17)
		// for a given release, but the jar's own embedded pom.properties
		// records only the bare numeric version, identically across every
		// classified build. The ranges below are reproduced verbatim from
		// the real OSV advisory data.
		{
			name: "mssql-jdbc/installed is the fixed build, classifier lost at indexing (reported false positive)",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.microsoft.sqlserver:mssql-jdbc",
					Version: "12.10.2",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-m494-w24q-6f7w",
				Description: "JDBC Driver for SQL Server has improper input validation issue",
				Package: &claircore.Package{
					Name:           "com.microsoft.sqlserver:mssql-jdbc",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=12.10.0.jre11&fixed=12.10.2.jre11",
			},
			want: false,
		},
		{
			name: "mssql-jdbc/second affected release line, same shape (customer-observed)",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.microsoft.sqlserver:mssql-jdbc",
					Version: "13.2.1",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-m494-w24q-6f7w",
				Description: "JDBC Driver for SQL Server has improper input validation issue",
				Package: &claircore.Package{
					Name:           "com.microsoft.sqlserver:mssql-jdbc",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=13.2.0.jre11&fixed=13.2.1.jre11",
			},
			want: false,
		},
		{
			name: "mssql-jdbc/installed is exactly the truncated introduced boundary (pre-existing latent false negative)",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.microsoft.sqlserver:mssql-jdbc",
					Version: "12.10.0",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-m494-w24q-6f7w",
				Description: "JDBC Driver for SQL Server has improper input validation issue",
				Package: &claircore.Package{
					Name:           "com.microsoft.sqlserver:mssql-jdbc",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=12.10.0.jre11&fixed=12.10.2.jre11",
			},
			want: true,
		},
		{
			name: "mssql-jdbc/genuinely older version must still be reported vulnerable",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.microsoft.sqlserver:mssql-jdbc",
					Version: "12.10.1",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-m494-w24q-6f7w",
				Description: "JDBC Driver for SQL Server has improper input validation issue",
				Package: &claircore.Package{
					Name:           "com.microsoft.sqlserver:mssql-jdbc",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=12.10.0.jre11&fixed=12.10.2.jre11",
			},
			want: true,
		},
		{
			name: "mssql-jdbc/genuinely newer version must still be reported not vulnerable",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.microsoft.sqlserver:mssql-jdbc",
					Version: "12.10.3",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-m494-w24q-6f7w",
				Description: "JDBC Driver for SQL Server has improper input validation issue",
				Package: &claircore.Package{
					Name:           "com.microsoft.sqlserver:mssql-jdbc",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=12.10.0.jre11&fixed=12.10.2.jre11",
			},
			want: false,
		},
		{
			name: "mssql-jdbc/below the introduced range entirely",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.microsoft.sqlserver:mssql-jdbc",
					Version: "11.9.9",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-m494-w24q-6f7w",
				Description: "JDBC Driver for SQL Server has improper input validation issue",
				Package: &claircore.Package{
					Name:           "com.microsoft.sqlserver:mssql-jdbc",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "introduced=12.10.0.jre11&fixed=12.10.2.jre11",
			},
			want: false,
		},
		{
			// A real Maven qualifier (here, "sp" for "service pack") must
			// keep normal ordering semantics: unlike an unrecognized
			// classifier, "-sp1" genuinely denotes a later, separately
			// released patch, not a simultaneously-published sibling build.
			name: "recognized qualifier (service pack) must not be short-circuited",
			record: &claircore.IndexRecord{
				Package: &claircore.Package{
					Name:    "com.example:widget",
					Version: "1.2.3",
					Kind:    types.BinaryPackage,
				},
			},
			vuln: &claircore.Vulnerability{
				Updater:     "osv",
				Name:        "GHSA-0000-0000-0000",
				Description: "fictitious vulnerability for test purposes",
				Package: &claircore.Package{
					Name:           "com.example:widget",
					RepositoryHint: "Maven",
				},
				FixedInVersion: "fixed=1.2.3-sp1",
			},
			want: true,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			got, err := matcher.Vulnerable(context.Background(), testcase.record, testcase.vuln)
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(got, testcase.want) {
				t.Error(cmp.Diff(got, testcase.want))
			}
		})
	}
}

func TestMatcher(t *testing.T) {
	test.RunMatcherTests(test.Logging(t), t, "testdata/matcher", new(Matcher))
}
