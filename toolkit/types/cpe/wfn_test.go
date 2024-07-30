package cpe

import (
	"bufio"
	"compress/gzip"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func valueAny() Value         { return Value{Kind: ValueAny} }
func valueNA() Value          { return Value{Kind: ValueNA} }
func valueSet(v string) Value { return Value{Kind: ValueSet, V: v} }

func TestValidate(t *testing.T) {
	t.Parallel()
	tt := []struct {
		In  string
		Err bool
	}{
		{"", false},
		{`foo\-bar`, false},             // hyphen is quoted
		{`Acrobat_Reader`, false},       // normal string
		{`\"oh_my\!\"`, false},          // quotation marks and exclamation point are quoted
		{`g\+\+`, false},                // plus signs are quoted
		{`9\.?`, false},                 // period is quoted, question mark is unquoted
		{`sr*`, false},                  // asterisk is unquoted
		{`big\$money`, false},           // dollar sign is quoted
		{`foo\:bar`, false},             // colon is quoted
		{`back\\slash_software`, false}, // backslash is quoted
		{`with_quoted\~tilde`, false},   // tilde is quoted
		{`*SOFT*`, false},               // single unquoted asterisk at beginning and end
		{`8\.??`, false},                // two unquoted question marks at end
		{`*8\.??`, false},               // one unquoted asterisk at beginning, two unquoted question marks at end

		// Our reading of the standard says these should be valid.
		{`?a?`, false},
		{`??a?`, false},
		{`?a??`, false},
		{`??a??`, false},

		{`*`, true},    // A single asterisk MUST NOT be used by itself as an attribute value.
		{`a*b`, true},  // A special character MUST NOT be embedded within a value string.
		{`a??b`, true}, // A special character MUST NOT be embedded within a value string.
		{`a?b`, true},  // A special character MUST NOT be embedded within a value string.
		{`sr**`, true}, // The asterisk MUST NOT be used more than once in sequence.
		{`\-`, true},   // A quoted hyphen MUST NOT be used by itself as a value string.
		{`]`, true},    // All other printable non-alphanumeric characters MUST be quoted when embedded in value strings.
		{` `, true},    // whitespace characters (which SHALL NOT be used)

		// Our reading of the standard says these should be invalid.
		{`a*?`, true},
		{`a?*`, true},
		{`*?a`, true},
		{`?*a`, true},
	}

	for _, tc := range tt {
		err := validate(tc.In)
		if tc.Err == (err == nil) {
			t.Errorf("%q got: %v", tc.In, err)
		}
	}
}

func TestValue(t *testing.T) {
	t.Run("OK", func(t *testing.T) {
		v, err := NewValue("test")
		if err != nil {
			t.Error(err)
		}
		t.Logf("%v", &v)
	})
	t.Run("Invalid", func(t *testing.T) {
		v, err := NewValue(" ")
		if err == nil {
			t.Error("error unexpectedly not-nil")
		}
		t.Logf("%v", &v)
	})
}

func TestBinding(t *testing.T) {
	t.Parallel()
	// BindTable is a table of WFN to string mappings copied out of the standards
	// document: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
	//
	// The wfn from the text is kept in a comment, then transcribed by hand into a
	// WFN literal, and the expected binding is copied verbatim.
	bindTable := []struct {
		Bound string
		WFN   WFN
	}{
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("microsoft"),
				valueSet("internet_explorer"),
				valueSet(`8\.0\.6001`),
				valueSet("beta"),
				valueAny(),
			}},
			Bound: `cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*`,
		},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.*",update="sp?",edition=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("microsoft"),
				valueSet("internet_explorer"),
				valueSet(`8\.*`),
				valueSet("sp?"),
			}},
			Bound: `cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*`,
		},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.\*",update="sp?"]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("microsoft"),
				valueSet("internet_explorer"),
				valueSet(`8\.\*`),
				valueSet("sp?"),
			}},
			Bound: `cpe:2.3:a:microsoft:internet_explorer:8.\*:sp?:*:*:*:*:*:*`,
		},
		// wfn:[part="a",vendor="hp",product="insight",version="7\.4\.0\.1570",update=NA,sw_edition="online",target_sw="win2003",target_hw="x64"]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("hp"),
				valueSet("insight"),
				valueSet(`7\.4\.0\.1570`),
				valueNA(),
				{},
				{},
				valueSet("online"),
				valueSet("win2003"),
				valueSet("x64"),
			}},
			Bound: `cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*`,
		},
		// wfn:[part="a",vendor="hp",product="openview_network_manager",version="7\.51",target_sw="linux"]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("hp"),
				valueSet("openview_network_manager"),
				valueSet(`7\.51`),
				{},
				{},
				{},
				{},
				valueSet("linux"),
			}},
			Bound: `cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*`,
		},
		// wfn:[part="a",vendor="foo\\bar",product="big\$money_2010",sw_edition="special",target_sw="ipod_touch",target_hw="80gb"]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet(`foo\\bar`),
				valueSet(`big\$money_2010`),
				{},
				{},
				{},
				{},
				valueSet("special"),
				valueSet("ipod_touch"),
				valueSet("80gb"),
			}},
			Bound: `cpe:2.3:a:foo\\bar:big\$money_2010:*:*:*:*:special:ipod_touch:80gb:*`,
		},
	}

	for _, tc := range bindTable {
		if got, want := tc.WFN.String(), tc.Bound; got != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	}
}

func TestUnbinding(t *testing.T) {
	t.Parallel()

	type unbindCase struct {
		Bound string
		WFN   WFN
		Error bool
	}
	inner := func(tcs []unbindCase, unbind func(string) (WFN, error)) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()
			for i, tc := range tcs {
				t.Logf("%02d: %q", i, tc.Bound)
				got, err := unbind(tc.Bound)
				if tc.Error {
					if err == nil {
						t.Errorf("%02d: expected error, got nil", i)
					}
					continue
				}
				if err != nil {
					t.Logf("%02d: %v", i, err)
				}
				if want := tc.WFN; !cmp.Equal(got, want) {
					t.Errorf("%02d: %v", i, cmp.Diff(got, want))
				}
			}
		}
	}

	// FsTable is a table of string to WFN mappings copied out of the standards
	// document: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
	//
	// The goal wfn from the text is kept in a comment, then transcribed by hand into a
	// WFN literal, and the starting binding is copied verbatim.
	fsTable := []unbindCase{
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY,language=ANY,sw_edition=ANY,target_sw=ANY,target_hw=ANY,other=ANY]
		{
			Bound: `cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*`,
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("microsoft"),
				valueSet("internet_explorer"),
				valueSet(`8\.0\.6001`),
				valueSet("beta"),
				valueAny(),
				valueAny(),
				valueAny(),
				valueAny(),
				valueAny(),
				valueAny(),
			}},
		},
		// wfn:[part="a",vendor="hp",product="insight_diagnostics",version="7\.4\.0\.1570",update=NA,edition=ANY,language=ANY,sw_edition="online",target_sw="win2003",target_hw="x64",other=ANY]
		{
			Bound: `cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*`,
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("hp"),
				valueSet("insight_diagnostics"),
				valueSet(`7\.4\.0\.1570`),
				valueNA(),
				valueAny(),
				valueAny(),
				valueSet("online"),
				valueSet("win2003"),
				valueSet("x64"),
				valueAny(),
			}},
		},
		// Invalid bound form because of unquoted (and misplaced) asterisk.
		{
			Bound: `cpe:2.3:a:hp:insight_diagnostics:7.4.*.1570:-:*:*:online:win2003:x64:*`,
			Error: true,
		},
		// wfn:[part="a",vendor="foo\\bar",product="big\$money",version="2010",update=ANY,edition=ANY,language=ANY,sw_edition="special",target_sw="ipod_touch",target_hw="80gb",other=ANY]
		{
			Bound: `cpe:2.3:a:foo\\bar:big\$money:2010:*:*:*:special:ipod_touch:80gb:*`,
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet(`foo\\bar`),
				valueSet(`big\$money`),
				valueSet("2010"),
				valueAny(),
				valueAny(),
				valueAny(),
				valueSet("special"),
				valueSet("ipod_touch"),
				valueSet("80gb"),
				valueAny(),
			}},
		},
	}

	// This table is made from the URI unbinding examples in the standards document.
	uriTable := []unbindCase{
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("microsoft"),
				valueSet("internet_explorer"),
				valueSet(`8\.0\.6001`),
				valueSet("beta"),
				valueAny(),
				valueAny(),
			}},
			Bound: `cpe:/a:microsoft:internet_explorer:8.0.6001:beta`,
		},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.\*",update="sp\?",edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("microsoft"),
				valueSet("internet_explorer"),
				valueSet(`8\.\*`),
				valueSet(`sp\?`),
				valueAny(),
				valueAny(),
			}},
			Bound: `cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f`,
		},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.*",update="sp?",edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("microsoft"),
				valueSet("internet_explorer"),
				valueSet(`8\.*`),
				valueSet("sp?"),
				valueAny(),
				valueAny(),
			}},
			Bound: `cpe:/a:microsoft:internet_explorer:8.%02:sp%01`,
		},
		// wfn:[part="a",vendor="hp",product="insight_diagnostics",version="7\.4\.0\.1570",update=ANY,edition=ANY,sw_edition="online",target_sw="win2003",target_hw="x64",other=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("hp"),
				valueSet("insight_diagnostics"),
				valueSet(`7\.4\.0\.1570`),
				valueAny(),
				valueAny(),
				valueAny(),
				valueSet("online"),
				valueSet("win2003"),
				valueSet("x64"),
				valueAny(),
			}},
			Bound: `cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~`,
		},
		// wfn:[part="a",vendor="hp",product="openview_network_manager",version="7\.51",update=NA,edition=ANY,sw_edition=ANY,target_sw="linux",target_HW=ANY,other=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("hp"),
				valueSet("openview_network_manager"),
				valueSet(`7\.51`),
				valueNA(),
				valueAny(),
				valueAny(),
				valueAny(),
				valueSet("linux"),
				valueAny(),
				valueAny(),
			}},
			Bound: `cpe:/a:hp:openview_network_manager:7.51:-:~~~linux~~`,
		},
		// An error is raised when this URI is unbound, because it contains an illegal percent-encoded form,"%07".
		{
			Bound: `cpe:/a:foo%5cbar:big%24money_2010%07:::~~special~ipod_touch~80gb~`,
			Error: true,
		},
		// wfn:[part="a",vendor="foo\~bar",product="big\~money_2010",version=ANY,update=ANY,edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet(`foo\~bar`),
				valueSet(`big\~money_2010`),
				valueAny(),
				valueAny(),
				valueAny(),
				valueAny(),
			}},
			Bound: `cpe:/a:foo~bar:big%7emoney_2010`,
		},
		// An error is raised when this URI is unbound, because it contains a special character ("%02") embedded within a valuestring.
		{Bound: `cpe:/a:foo:bar:12.%02.1234`, Error: true},
		// Errors because of a disallowed character.
		{Bound: `cpe:/a:redhat:openshift:4.*`, Error: true},
		// Should be fine, because it's just short.
		{
			Bound: `cpe:/a:redhat:openshift:4`,
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("redhat"),
				valueSet("openshift"),
				valueSet("4"),
				valueAny(),
				valueAny(),
				valueAny(),
			}},
		},
		// Should be fine, because a wildcard is in an allowed state.
		{
			Bound: `cpe:/a:redhat:openshift:4.%02`,
			WFN: WFN{Attr: [NumAttr]Value{
				valueSet("a"),
				valueSet("redhat"),
				valueSet("openshift"),
				valueSet(`4\.*`),
				valueAny(),
				valueAny(),
				valueAny(),
			}},
		},
	}

	t.Run("FS", inner(fsTable, UnbindFS))
	t.Run("URI", inner(uriTable, UnbindURI))
}

func TestDictionary(t *testing.T) {
	const fmt = "line #%02d:\nin:\t%+q\ngot:\t%q\nwant:\t%q"
	t.Parallel()
	f, err := os.Open("testdata/dictionary.list.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	s := bufio.NewScanner(gz)
	for i := 1; s.Scan(); i++ {
		fs := strings.Split(s.Text(), "\t")
		want := fs[1]
		for _, in := range fs {
			wfn, err := Unbind(in)
			if err != nil {
				t.Fatal(err)
				t.Fatalf("%v: %#q", err, in)
			}
			if got := wfn.BindFS(); got != want {
				t.Logf(fmt, i, in, got, want)
				t.Logf("wfn: %#v", wfn)
				t.Fail()
			}
		}
	}
	if err := s.Err(); err != nil {
		t.Error(err)
	}
}
