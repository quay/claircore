package pyupio

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test/log"
)

func TestDB(t *testing.T) {
	tt := []dbTestcase{
		{
			Name: "django-cms",
			Want: []*claircore.Vulnerability{
				&claircore.Vulnerability{
					Name:           "pyup.io-25741",
					Description:    "django-cms 2.1.3 fixes a serious security issue in PlaceholderAdmin",
					Package:        &claircore.Package{Name: "django-cms", Kind: claircore.BINARY},
					FixedInVersion: "2.1.3",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 2, 1, 3, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-25742",
					Description:    "django-cms before 2.1.4 fixes a XSS issue in Text Plugins.",
					Package:        &claircore.Package{Name: "django-cms", Kind: claircore.BINARY},
					FixedInVersion: "2.1.4",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 2, 1, 4, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-25743",
					Description:    "django-cms 3.0.14 fixes an issue where privileged users could be tricked into performing actions without their knowledge via a CSRF vulnerability",
					Package:        &claircore.Package{Name: "django-cms", Kind: claircore.BINARY},
					FixedInVersion: "3.0.14",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 3, 0, 14, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-25746",
					Description:    "django-cms  3.2.4 addresses security vulnerabilities in the `render_model` template tag that could lead to escalation of privileges or other security issues. It also addresses a security vulnerability in the cms' usage of the messages framework. Furthermore it fixes security vulnerabilities in custom FormFields that could lead to escalation of privileges or other security issue",
					Package:        &claircore.Package{Name: "django-cms", Kind: claircore.BINARY},
					FixedInVersion: "3.2.4",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 3, 2, 4, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-34226",
					Description:    "django-cms 3.4.3 fixes a security vulnerability in the page redirect field which allowed users to insert JavaScript code and a vulnerability where the next parameter for the toolbar login was not sanitised and could point to another domain.",
					Package:        &claircore.Package{Name: "django-cms", Kind: claircore.BINARY},
					FixedInVersion: "3.4.3",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 3, 4, 3, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-35628 (CVE-2015-5081)",
					Description:    "Cross-site request forgery (CSRF) vulnerability in django CMS before 3.0.14, 3.1.x before 3.1.1 allows remote attackers to manipulate privileged users into performing unknown actions via unspecified vectors.",
					Package:        &claircore.Package{Name: "django-cms", Kind: claircore.BINARY},
					FixedInVersion: "3.0.14",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 3, 0, 14, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-35628 (CVE-2015-5081)",
					Description:    "Cross-site request forgery (CSRF) vulnerability in django CMS before 3.0.14, 3.1.x before 3.1.1 allows remote attackers to manipulate privileged users into performing unknown actions via unspecified vectors.",
					Package:        &claircore.Package{Name: "django-cms", Kind: claircore.BINARY},
					FixedInVersion: "3.1.1",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 3, 1, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 3, 1, 1, 0, 0, 0, 0, 0, 0}},
					},
				},
			},
		},
		{
			Name: "bottle",
			Want: []*claircore.Vulnerability{
				&claircore.Vulnerability{
					Name:           "pyup.io-25642 (CVE-2016-9964)",
					Description:    `redirect() in bottle.py in bottle 0.12.10 doesn't filter a "\r\n" sequence, which leads to a CRLF attack, as demonstrated by a redirect("233\r\nSet-Cookie: name=salt") call.`,
					Package:        &claircore.Package{Name: "bottle", Kind: claircore.BINARY},
					FixedInVersion: "0.12.10",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 12, 10, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-35548 (CVE-2014-3137)",
					Description:    "Bottle 0.10.x before 0.10.12, 0.11.x before 0.11.7, and 0.12.x before 0.12.6 does not properly limit content types, which allows remote attackers to bypass intended access restrictions via an accepted Content-Type followed by a ; (semi-colon) and a Content-Type that would not be accepted, as demonstrated in YouCompleteMe to execute arbitrary code.",
					Package:        &claircore.Package{Name: "bottle", Kind: claircore.BINARY},
					FixedInVersion: "0.10.12",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 10, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 10, 12, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-35548 (CVE-2014-3137)",
					Description:    "Bottle 0.10.x before 0.10.12, 0.11.x before 0.11.7, and 0.12.x before 0.12.6 does not properly limit content types, which allows remote attackers to bypass intended access restrictions via an accepted Content-Type followed by a ; (semi-colon) and a Content-Type that would not be accepted, as demonstrated in YouCompleteMe to execute arbitrary code.",
					Package:        &claircore.Package{Name: "bottle", Kind: claircore.BINARY},
					FixedInVersion: "0.11.7",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 11, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 11, 7, 0, 0, 0, 0, 0, 0}},
					},
				},
				&claircore.Vulnerability{
					Name:           "pyup.io-35548 (CVE-2014-3137)",
					Description:    "Bottle 0.10.x before 0.10.12, 0.11.x before 0.11.7, and 0.12.x before 0.12.6 does not properly limit content types, which allows remote attackers to bypass intended access restrictions via an accepted Content-Type followed by a ; (semi-colon) and a Content-Type that would not be accepted, as demonstrated in YouCompleteMe to execute arbitrary code.",
					Package:        &claircore.Package{Name: "bottle", Kind: claircore.BINARY},
					FixedInVersion: "0.12.6",
					Range: &claircore.Range{
						Lower: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 12, 0, 0, 0, 0, 0, 0, 0}},
						Upper: claircore.Version{Kind: "pep440", V: [...]int32{0, 0, 12, 6, 0, 0, 0, 0, 0, 0}},
					},
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
	Want []*claircore.Vulnerability
}

func (tc dbTestcase) filename() string {
	return filepath.Join("testdata", fmt.Sprintf("db_%s.json", tc.Name))
}

func (tc dbTestcase) Run(t *testing.T) {
	ctx := context.Background()
	ctx, done := log.TestLogger(ctx, t)
	defer done()

	f, err := os.Open(tc.filename())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var db db
	if err := json.NewDecoder(f).Decode(&db); err != nil {
		t.Fatal(err)
	}

	got, err := db.Vulnerabilites(ctx, nil, "")
	if err != nil {
		t.Error(err)
	}
	// Sort for the comparison, because the Vulnerabilities method can return
	// the slice in any order.
	sort.SliceStable(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	if !cmp.Equal(tc.Want, got) {
		t.Error(cmp.Diff(tc.Want, got))
	}
}
