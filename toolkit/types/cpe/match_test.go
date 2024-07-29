package cpe

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"text/tabwriter"

	"github.com/google/go-cmp/cmp"
)

func TestMatch(t *testing.T) {
	t.Parallel()
	type testcase struct {
		Source string
		Target string
		Want   Relations
	}

	// There seems to be no test vectors for the match specification.
	matchTable := []testcase{
		{
			Source: `cpe:/a:Adobe::9.%02::PalmOS`,
			Target: `cpe:/a::Reader:9.3.2:-:-`,
			Want: Relations([NumAttr]Relation{
				Equal, Subset, Superset, Superset, Superset, Disjoint, Equal, Equal, Equal, Equal, Equal,
			}),
		},
		// Check that comparing across CPE versions works:
		{
			Source: `cpe:/o:redhat:enterprise_linux:8::baseos`,
			Target: `cpe:/o:redhat:enterprise_linux:8`,
			Want: Relations([NumAttr]Relation{
				Equal, Equal, Equal, Equal, Equal, Subset, Equal, Equal, Equal, Equal, Equal,
			}),
		},
		{
			Source: MustUnbind(`cpe:/o:redhat:enterprise_linux:8::baseos`).String(),
			Target: MustUnbind(`cpe:/o:redhat:enterprise_linux:8`).String(),
			Want: Relations([NumAttr]Relation{
				Equal, Equal, Equal, Equal, Equal, Subset, Equal, Equal, Equal, Equal, Equal,
			}),
		},
		{
			Source: MustUnbind(`cpe:/o:redhat:enterprise_linux:8::baseos`).String(),
			Target: `cpe:/o:redhat:enterprise_linux:8`,
			Want: Relations([NumAttr]Relation{
				Equal, Equal, Equal, Equal, Equal, Subset, Equal, Equal, Equal, Equal, Equal,
			}),
		},
		{
			Source: `cpe:/o:redhat:enterprise_linux:8::baseos`,
			Target: MustUnbind(`cpe:/o:redhat:enterprise_linux:8`).String(),
			Want: Relations([NumAttr]Relation{
				Equal, Equal, Equal, Equal, Equal, Subset, Equal, Equal, Equal, Equal, Equal,
			}),
		},
		{
			Source: `cpe:2.3:a:redhat:openshift:4.*:*:el8:*:*:*:*:*`,
			Target: `cpe:2.3:a:redhat:openshift:5.1:*:el8:*:*:*:*:*`,
			Want: Relations([NumAttr]Relation{
				Equal, Equal, Equal, Disjoint, Equal, Equal, Equal, Equal, Equal, Equal, Equal,
			}),
		},
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 3, 4, 1, ' ', 0)
	for _, tc := range matchTable {
		t.Run("", func(t *testing.T) {
			src, tgt := MustUnbind(tc.Source), MustUnbind(tc.Target)
			got, want := Compare(src, tgt), tc.Want

			buf.Reset()
			fmt.Fprintf(w, "source:%s\n", tabfmtWFN(src))
			fmt.Fprintf(w, "target:%s\n", tabfmtWFN(tgt))
			fmt.Fprintf(w, "got:%s\n", tabfmtRelations(got))
			fmt.Fprintf(w, "want:%s\n", tabfmtRelations(want))
			w.Flush()
			t.Logf("state:\n%s", buf.String())

			buf.Reset()
			tabfmtResults(w, got)
			w.Flush()
			t.Logf("results:\n%s", buf.String())

			if !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}

func tabfmtWFN(w WFN) string {
	var b strings.Builder
	for _, a := range w.Attr {
		b.WriteByte('\t')
		switch a.Kind {
		case ValueUnset:
			b.WriteString("∅")
		case ValueAny:
			b.WriteString("ANY")
		case ValueNA:
			b.WriteString("NA")
		case ValueSet:
			b.WriteString(strconv.Quote(a.V))
		}
	}
	return b.String()
}

func tabfmtRelations(r Relations) string {
	var b strings.Builder
	for _, r := range r {
		b.WriteByte('\t')
		b.WriteString(r.String())
	}
	return b.String()
}

func tabfmtResults(w io.Writer, r Relations) {
	for _, x := range []struct {
		rel string
		val bool
	}{
		{"superset", r.IsSuperset()},
		{"subset", r.IsSubset()},
		{"equal", r.IsEqual()},
		{"disjoint", r.IsDisjoint()},
	} {
		fmt.Fprintf(w, "%s?\t%v\n", x.rel, x.val)
	}
}

func TestPatternCompare(t *testing.T) {
	t.Parallel()
	type testcase struct {
		Source string
		Target string
		Want   bool
	}
	var b strings.Builder
	eq := func(ok bool) string {
		if ok {
			return `⩵`
		}
		return `≠`
	}

	table := []testcase{
		{`4\.*`, `5\.1`, false},
	}
	for _, tc := range table {
		t.Run("", func(t *testing.T) {
			b.Reset()
			got, want := patCompare(tc.Source, tc.Target), tc.Want
			fmt.Fprintf(&b, "got: %#q %s %#q", tc.Source, eq(got), tc.Target)
			if got != want {
				fmt.Fprintf(&b, ", want: %#q %s %#q", tc.Source, eq(want), tc.Target)
				t.Fail()
			}
			t.Log(b.String())
		})
	}
}
