package ovalutil

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/goval-parser/oval"
)

// TestWalk tests the recursive criterion walker.
func TestWalk(t *testing.T) {
	t.Parallel()

	type testcase struct {
		File  string
		Index int
		Want  []string
	}
	testcases := []testcase{
		{
			File:  "../../oracle/testdata/com.oracle.elsa-2018.xml",
			Index: 199,
			Want: []string{
				`Oracle Linux 7 is installed AND ghostscript is earlier than 0:9.07-31.el7_6.3 AND ghostscript is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-cups is earlier than 0:9.07-31.el7_6.3 AND ghostscript-cups is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-devel is earlier than 0:9.07-31.el7_6.3 AND ghostscript-devel is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-doc is earlier than 0:9.07-31.el7_6.3 AND ghostscript-doc is signed with the Oracle Linux 7 key`,
				`Oracle Linux 7 is installed AND ghostscript-gtk is earlier than 0:9.07-31.el7_6.3 AND ghostscript-gtk is signed with the Oracle Linux 7 key`,
			},
		},
		{
			File:  "../../rhel/testdata/Red_Hat_Enterprise_Linux_3.xml",
			Index: 42,
			Want: []string{
				`Red Hat Enterprise Linux 3 is installed AND samba-common is earlier than 0:3.0.9-1.3E.10 AND samba-common is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 3 is installed AND samba is earlier than 0:3.0.9-1.3E.10 AND samba is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 3 is installed AND samba-swat is earlier than 0:3.0.9-1.3E.10 AND samba-swat is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 3 is installed AND samba-client is earlier than 0:3.0.9-1.3E.10 AND samba-client is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba-common is earlier than 0:3.0.10-1.4E.6.2 AND samba-common is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba-client is earlier than 0:3.0.10-1.4E.6.2 AND samba-client is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba is earlier than 0:3.0.10-1.4E.6.2 AND samba is signed with Red Hat master key`,
				`Red Hat Enterprise Linux 4 is installed AND samba-swat is earlier than 0:3.0.10-1.4E.6.2 AND samba-swat is signed with Red Hat master key`,
			},
		},
	}

	runtest := func(c testcase) func(*testing.T) {
		// Must be the value, because of how ranges work, remember.
		return func(t *testing.T) {
			t.Parallel()

			// First, go open up the file and de-xml it.
			f, err := os.Open(c.File)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var root oval.Root
			if err := xml.NewDecoder(f).Decode(&root); err != nil {
				t.Error(err)
			}
			defs := root.Definitions.Definitions
			if len(defs) < c.Index {
				t.Fatalf("len(defs) = %d, less than %d", len(defs), c.Index)
			}

			// Then, do the walk.
			cr, err := walk(&defs[c.Index].Criteria)
			if err != nil {
				t.Fatal(err)
			}
			// And make some pretty strings.
			got := make([]string, len(cr))
			for i, cs := range cr {
				b := strings.Builder{}
				for i, c := range cs {
					if i != 0 {
						b.WriteString(" AND ")
					}
					b.WriteString(c.Comment)
				}
				got[i] = b.String()
				t.Log(b.String())
			}

			// Finally, compare our pretty strings.
			if got, want := len(got), len(c.Want); got != want {
				t.Errorf("got: len(got) == %d, want: len(got) == %d", got, want)
			}
			for i := range c.Want {
				if i > len(got) {
					break
				}
				if got, want := got[i], c.Want[i]; got != want {
					t.Errorf("got: %q, want: %q", got, want)
				}
			}
		}
	}

	for _, c := range testcases {
		t.Run(filepath.Base(c.File), runtest(c))
	}
}
