package rhel

import (
	"context"
	"encoding/xml"
	"os"
	"testing"

	"github.com/quay/goval-parser/oval"

	"github.com/quay/claircore/test/log"
)

func TestParse(t *testing.T) {
	t.Parallel()
	ctx, done := context.WithCancel(context.Background())
	defer done()
	ctx = log.TestLogger(ctx, t)
	u, err := NewUpdater(3)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("testdata/Red_Hat_Enterprise_Linux_3.xml")
	if err != nil {
		t.Fatal(err)
	}

	vs, err := u.Parse(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found %d vulnerabilities", len(vs))
	// I think there's 3510 vulnerabilities in the rhel3 database, including the
	// EOL notices.
	if got, want := len(vs), 3510; got != want {
		t.Fatalf("got: %d vulnerabilities, want: %d vulnerabilities", got, want)
	}
}

// Here's a giant restructured struct for reference and tests.
var ovalDef = oval.Definition{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "definition"},
	ID:    "oval:com.redhat.rhsa:def:20100401",
	Class: "patch",
	Title: "RHSA-2010:0401: tetex security update (Moderate)",
	Affecteds: []oval.Affected{
		oval.Affected{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "affected"},
			Family:    "unix",
			Platforms: []string{"Red Hat Enterprise Linux 3"}}},
	References: []oval.Reference{
		oval.Reference{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "reference"},
			Source: "RHSA",
			RefID:  "RHSA-2010:0401",
			RefURL: "https://access.redhat.com/errata/RHSA-2010:0401"},
		oval.Reference{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "reference"},
			Source: "CVE",
			RefID:  "CVE-2007-5935",
			RefURL: "https://access.redhat.com/security/cve/CVE-2007-5935"},
		oval.Reference{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "reference"},
			Source: "CVE",
			RefID:  "CVE-2009-0791",
			RefURL: "https://access.redhat.com/security/cve/CVE-2009-0791"},
		oval.Reference{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "reference"},
			Source: "CVE",
			RefID:  "CVE-2009-3609",
			RefURL: "https://access.redhat.com/security/cve/CVE-2009-3609"},
		oval.Reference{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "reference"},
			Source: "CVE",
			RefID:  "CVE-2010-0739",
			RefURL: "https://access.redhat.com/security/cve/CVE-2010-0739"},
		oval.Reference{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "reference"},
			Source: "CVE",
			RefID:  "CVE-2010-0827",
			RefURL: "https://access.redhat.com/security/cve/CVE-2010-0827"},
		oval.Reference{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "reference"},
			Source: "CVE",
			RefID:  "CVE-2010-1440",
			RefURL: "https://access.redhat.com/security/cve/CVE-2010-1440"}},
	Description: "teTeX is an implementation of TeX. TeX takes a text file and a set of\nformatting commands as input, and creates a typesetter-independent DeVice\nIndependent (DVI) file as output.\n\nA buffer overflow flaw was found in the way teTeX processed virtual font\nfiles when converting DVI files into PostScript. An attacker could create a\nmalicious DVI file that would cause the dvips executable to crash or,\npotentially, execute arbitrary code. (CVE-2010-0827)\n\nMultiple integer overflow flaws were found in the way teTeX processed\nspecial commands when converting DVI files into PostScript. An attacker\ncould create a malicious DVI file that would cause the dvips executable to\ncrash or, potentially, execute arbitrary code. (CVE-2010-0739,\nCVE-2010-1440)\n\nA stack-based buffer overflow flaw was found in the way teTeX processed DVI\nfiles containing HyperTeX references with long titles, when converting them\ninto PostScript. An attacker could create a malicious DVI file that would\ncause the dvips executable to crash. (CVE-2007-5935)\n\nteTeX embeds a copy of Xpdf, an open source Portable Document Format (PDF)\nfile viewer, to allow adding images in PDF format to the generated PDF\ndocuments. The following issues affect Xpdf code:\n\nMultiple integer overflow flaws were found in Xpdf. If a local user\ngenerated a PDF file from a TeX document, referencing a specially-crafted\nPDF file, it would cause Xpdf to crash or, potentially, execute arbitrary\ncode with the privileges of the user running pdflatex. (CVE-2009-0791,\nCVE-2009-3609)\n\nAll users of tetex are advised to upgrade to these updated packages, which\ncontain backported patches to correct these issues.",
	Advisory: oval.Advisory{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "advisory"},
		Severity: "Moderate",
		Cves: []oval.Cve{
			oval.Cve{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "cve"},
				CveID:  "CVE-2007-5935",
				Cvss2:  "",
				Cvss3:  "",
				Cwe:    "",
				Impact: "low",
				Href:   "https://access.redhat.com/security/cve/CVE-2007-5935",
				Public: "20071017"},
			oval.Cve{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "cve"},
				CveID:  "CVE-2009-0791",
				Cvss2:  "5.8/AV:A/AC:L/Au:N/C:P/I:P/A:P",
				Cvss3:  "",
				Cwe:    "CWE-190",
				Impact: "",
				Href:   "https://access.redhat.com/security/cve/CVE-2009-0791",
				Public: "20090519"},
			oval.Cve{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "cve"},
				CveID:  "CVE-2009-3609",
				Cvss2:  "2.1/AV:L/AC:L/Au:N/C:N/I:N/A:P",
				Cvss3:  "",
				Cwe:    "CWE-190",
				Impact: "low",
				Href:   "https://access.redhat.com/security/cve/CVE-2009-3609",
				Public: "20091014"},
			oval.Cve{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "cve"},
				CveID:  "CVE-2010-0739",
				Cvss2:  "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P",
				Cvss3:  "",
				Cwe:    "CWE-190",
				Impact: "",
				Href:   "https://access.redhat.com/security/cve/CVE-2010-0739",
				Public: "20100412"},
			oval.Cve{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "cve"},
				CveID:  "CVE-2010-0827",
				Cvss2:  "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P",
				Cvss3:  "",
				Cwe:    "",
				Impact: "",
				Href:   "https://access.redhat.com/security/cve/CVE-2010-0827",
				Public: "20100325"},
			oval.Cve{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "cve"},
				CveID:  "CVE-2010-1440",
				Cvss2:  "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P",
				Cvss3:  "",
				Cwe:    "CWE-190",
				Impact: "",
				Href:   "https://access.redhat.com/security/cve/CVE-2010-1440",
				Public: "20100503"}},
		Bugzillas: []oval.Bugzilla{
			oval.Bugzilla{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "bugzilla"},
				ID:    "368591",
				URL:   "https://bugzilla.redhat.com/368591",
				Title: "CVE-2007-5935 dvips -z buffer overflow with long href"},
			oval.Bugzilla{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "bugzilla"},
				ID:    "491840",
				URL:   "https://bugzilla.redhat.com/491840",
				Title: "CVE-2009-0791 xpdf: multiple integer overflows"},
			oval.Bugzilla{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "bugzilla"},
				ID:    "526893",
				URL:   "https://bugzilla.redhat.com/526893",
				Title: "CVE-2009-3609 xpdf/poppler: ImageStream::ImageStream integer overflow"},
			oval.Bugzilla{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "bugzilla"},
				ID:    "572914",
				URL:   "https://bugzilla.redhat.com/572914",
				Title: "CVE-2010-0827 tetex, texlive: Buffer overflow flaw by processing virtual font files"},
			oval.Bugzilla{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "bugzilla"},
				ID:    "572941",
				URL:   "https://bugzilla.redhat.com/572941",
				Title: "CVE-2010-0739 tetex, texlive: Integer overflow by processing special commands"},
			oval.Bugzilla{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "bugzilla"},
				ID:    "586819",
				URL:   "https://bugzilla.redhat.com/586819",
				Title: "CVE-2010-1440 tetex, texlive: Integer overflow by processing special commands"}},
		AffectedCPEList: []string{"cpe:/o:redhat:enterprise_linux:3"},
		Refs:            []oval.Ref(nil),
		Bugs:            []oval.Bug(nil),
		Issued: struct {
			Date string "xml:\"date,attr\""
		}{
			Date: "2010-05-06"},
		Updated: struct {
			Date string "xml:\"date,attr\""
		}{
			Date: "2010-05-06"}},
	Debian: oval.Debian{XMLName: xml.Name{Space: "", Local: ""}, MoreInfo: "", Date: ""},
	Criteria: oval.Criteria{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
		Operator: "AND",
		Criterias: []oval.Criteria{
			oval.Criteria{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
				Operator: "OR",
				Criterias: []oval.Criteria{
					oval.Criteria{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
						Operator:  "AND",
						Criterias: []oval.Criteria(nil),
						Criterions: []oval.Criterion{
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20100401001",
								Comment: "tetex-xdvi is earlier than 0:1.0.7-67.19"},
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20060160004",
								Comment: "tetex-xdvi is signed with Red Hat master key"}}},
					oval.Criteria{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
						Operator:  "AND",
						Criterias: []oval.Criteria(nil),
						Criterions: []oval.Criterion{
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20100401003",
								Comment: "tetex-fonts is earlier than 0:1.0.7-67.19"},
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20060160012",
								Comment: "tetex-fonts is signed with Red Hat master key"}}},
					oval.Criteria{
						XMLName:   xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
						Operator:  "AND",
						Criterias: []oval.Criteria(nil),
						Criterions: []oval.Criterion{
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20100401005",
								Comment: "tetex-dvips is earlier than 0:1.0.7-67.19"},
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20060160008",
								Comment: "tetex-dvips is signed with Red Hat master key"}}},
					oval.Criteria{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
						Operator:  "AND",
						Criterias: []oval.Criteria(nil),
						Criterions: []oval.Criterion{
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20100401007",
								Comment: "tetex is earlier than 0:1.0.7-67.19"},
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20060160002",
								Comment: "tetex is signed with Red Hat master key"}}},
					oval.Criteria{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
						Operator:  "AND",
						Criterias: []oval.Criteria(nil),
						Criterions: []oval.Criterion{
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20100401009",
								Comment: "tetex-afm is earlier than 0:1.0.7-67.19"},
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20060160010",
								Comment: "tetex-afm is signed with Red Hat master key"}}},
					oval.Criteria{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criteria"},
						Operator:  "AND",
						Criterias: []oval.Criteria(nil),
						Criterions: []oval.Criterion{
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20100401011",
								Comment: "tetex-latex is earlier than 0:1.0.7-67.19"},
							oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
								Negate:  false,
								TestRef: "oval:com.redhat.rhsa:tst:20060160006",
								Comment: "tetex-latex is signed with Red Hat master key"}}}},
				Criterions: []oval.Criterion(nil)}},
		Criterions: []oval.Criterion{
			oval.Criterion{XMLName: xml.Name{Space: "http://oval.mitre.org/XMLSchema/oval-definitions-5", Local: "criterion"},
				Negate:  false,
				TestRef: "oval:com.redhat.rhba:tst:20070026003",
				Comment: "Red Hat Enterprise Linux 3 is installed"}}}}
