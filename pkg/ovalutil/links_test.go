package ovalutil

import (
	"reflect"
	"strings"
	"testing"

	"github.com/quay/goval-parser/oval"
)

type linksTypeTestCase struct {
	name string
	want string
	def  oval.Definition
}

func TestLinksDeduplication(t *testing.T) {
	testCases := []linksTypeTestCase{
		{
			def: oval.Definition{
				References: []oval.Reference{
					{
						RefURL: "",
					},
				},
				Advisory: oval.Advisory{
					Refs: []oval.Ref{
						{
							URL: "",
						},
					},
					Bugs: []oval.Bug{
						{
							URL: "",
						},
					},
					Cves: []oval.Cve{
						{
							Href: "",
						},
					},
				},
			},
			want: "",
			name: "No fields populated",
		},
		{
			def: oval.Definition{
				References: []oval.Reference{
					{
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708",
					},
				},
				Advisory: oval.Advisory{
					Refs: []oval.Ref{
						{
							URL: "https://access.redhat.com/errata/RHSA-2022:8832",
						},
					},
					Bugs: []oval.Bug{
						{
							URL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708",
						},
					},
					Cves: []oval.Cve{
						{
							Href: "https://access.redhat.com/security/cve/cve-2023-4380",
						},
					},
				},
			},
			want: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708 https://access.redhat.com/errata/RHSA-2022:8832 https://access.redhat.com/security/cve/cve-2023-4380",
			name: "All fields populated, one duplicate link",
		},
		{
			def: oval.Definition{
				References: []oval.Reference{
					{
						RefURL: "https://access.redhat.com/errata/RHSA-2022:8832",
					},
				},
			},
			want: "https://access.redhat.com/errata/RHSA-2022:8832",
			name: "Just References",
		},
		{
			def: oval.Definition{
				References: []oval.Reference{
					{
						RefURL: "",
					},
				},
				Advisory: oval.Advisory{
					Cves: []oval.Cve{
						{
							Href: "https://access.redhat.com/security/cve/cve-2023-4380",
						},
						{
							Href: "https://access.redhat.com/security/cve/cve-2023-4380",
						},
						{
							Href: "https://access.redhat.com/security/cve/cve-2023-4381",
						},
					},
				},
			},
			want: "https://access.redhat.com/security/cve/cve-2023-4380 https://access.redhat.com/security/cve/cve-2023-4381",
			name: "Blank References RefURL, multiple Cves",
		},
		{
			def: oval.Definition{
				References: []oval.Reference{
					{
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708",
					},
					{
						RefURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37709",
					},
				},
				Advisory: oval.Advisory{
					Refs: []oval.Ref{
						{
							URL: "https://access.redhat.com/errata/RHSA-2022:8832",
						},
						{
							URL: "",
						},
						{
							URL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708",
						},
					},
					Bugs: []oval.Bug{
						{
							URL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708",
						},
						{
							URL: "https://access.redhat.com/errata/RHSA-2022:8832",
						},
						{
							URL: "https://access.redhat.com/errata/RHSA-2022:8833",
						},
					},
					Cves: []oval.Cve{
						{
							Href: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708",
						},
						{
							Href: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37709",
						},
						{
							Href: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1245",
						},
						{
							Href: "",
						},
					},
				},
			},
			want: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37708 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-37709 https://access.redhat.com/errata/RHSA-2022:8832 https://access.redhat.com/errata/RHSA-2022:8833 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1245",
			name: "All fields populated, with duplicates across multiple potential areas including blanks",
		},
	}

	for _, tc := range testCases {
		got := strings.Split(Links(tc.def), " ")
		want := strings.Split(tc.want, " ")

		if !reflect.DeepEqual(want, got) {
			t.Errorf("%q failed: want %q, got %q", tc.name, want, got)
		}
	}
}
