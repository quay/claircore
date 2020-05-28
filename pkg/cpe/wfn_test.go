package cpe

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestValidate(t *testing.T) {
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

func TestBinding(t *testing.T) {
	// BindTable is a table of WFN to string mappings copied out of the standards
	// document: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
	//
	// The wfn from the text is kept in a comment, then transcribed by hand into a
	// WFN literal, and the expected binding is copied verbatim.
	var bindTable = []struct {
		WFN   WFN
		Bound string
	}{
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY]
		{
			WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "microsoft"},
				{Kind: ValueSet, V: "internet_explorer"},
				{Kind: ValueSet, V: "8\\.0\\.6001"},
				{Kind: ValueSet, V: "beta"},
				{Kind: ValueAny},
				{},
				{},
				{},
				{},
				{},
			}},
			`cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*`,
		},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.*",update="sp?",edition=ANY]
		{
			WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "microsoft"},
				{Kind: ValueSet, V: "internet_explorer"},
				{Kind: ValueSet, V: "8\\.*"},
				{Kind: ValueSet, V: "sp?"},
				{},
				{},
				{},
				{},
				{},
				{},
			}},
			`cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*`,
		},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.\*",update="sp?"]
		{
			WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "microsoft"},
				{Kind: ValueSet, V: "internet_explorer"},
				{Kind: ValueSet, V: "8\\.\\*"},
				{Kind: ValueSet, V: "sp?"},
				{},
				{},
				{},
				{},
				{},
				{},
			}},
			`cpe:2.3:a:microsoft:internet_explorer:8.\*:sp?:*:*:*:*:*:*`,
		},
		// wfn:[part="a",vendor="hp",product="insight",version="7\.4\.0\.1570",update=NA,sw_edition="online",target_sw="win2003",target_hw="x64"]
		{
			WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "hp"},
				{Kind: ValueSet, V: "insight"},
				{Kind: ValueSet, V: `7\.4\.0\.1570`},
				{Kind: ValueNA},
				{},
				{},
				{Kind: ValueSet, V: "online"},
				{Kind: ValueSet, V: "win2003"},
				{Kind: ValueSet, V: "x64"},
				{},
			}},
			`cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*`,
		},
		// wfn:[part="a",vendor="hp",product="openview_network_manager",version="7\.51",target_sw="linux"]
		{
			WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "hp"},
				{Kind: ValueSet, V: "openview_network_manager"},
				{Kind: ValueSet, V: `7\.51`},
				{},
				{},
				{},
				{},
				{Kind: ValueSet, V: "linux"},
				{},
				{},
			}},
			`cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*`,
		},
		// wfn:[part="a",vendor="foo\\bar",product="big\$money_2010",sw_edition="special",target_sw="ipod_touch",target_hw="80gb"]
		{
			WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: `foo\\bar`},
				{Kind: ValueSet, V: `big\$money_2010`},
				{},
				{},
				{},
				{},
				{Kind: ValueSet, V: "special"},
				{Kind: ValueSet, V: "ipod_touch"},
				{Kind: ValueSet, V: "80gb"},
				{},
			}},
			`cpe:2.3:a:foo\\bar:big\$money_2010:*:*:*:*:special:ipod_touch:80gb:*`,
		},
	}

	for _, tc := range bindTable {
		if got, want := tc.WFN.String(), tc.Bound; got != want {
			t.Errorf("got: %v, want: %v", got, want)
		}
	}
}

func TestUnbinding(t *testing.T) {
	// UnbindTable is a table of string to WFN mappings copied out of the standards
	// document: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
	//
	// The goal wfn from the text is kept in a comment, then transcribed by hand into a
	// WFN literal, and the starting binding is copied verbatim.
	var unbindTable = []struct {
		Bound string
		WFN   WFN
		Error bool
	}{
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY,language=ANY,sw_edition=ANY,target_sw=ANY,target_hw=ANY,other=ANY]
		{
			Bound: `cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*`,
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "microsoft"},
				{Kind: ValueSet, V: "internet_explorer"},
				{Kind: ValueSet, V: "8\\.0\\.6001"},
				{Kind: ValueSet, V: "beta"},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueAny},
			}},
		},
		// wfn:[part="a",vendor="hp",product="insight_diagnostics",version="7\.4\.0\.1570",update=NA,edition=ANY,language=ANY,sw_edition="online",target_sw="win2003",target_hw="x64",other=ANY]
		{
			Bound: `cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*`,
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "hp"},
				{Kind: ValueSet, V: "insight_diagnostics"},
				{Kind: ValueSet, V: `7\.4\.0\.1570`},
				{Kind: ValueNA},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueSet, V: "online"},
				{Kind: ValueSet, V: "win2003"},
				{Kind: ValueSet, V: "x64"},
				{Kind: ValueAny},
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
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: `foo\\bar`},
				{Kind: ValueSet, V: `big\$money`},
				{Kind: ValueSet, V: "2010"},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueSet, V: "special"},
				{Kind: ValueSet, V: "ipod_touch"},
				{Kind: ValueSet, V: "80gb"},
				{Kind: ValueAny},
			}},
		},
	}
	for _, tc := range unbindTable {
		t.Logf("%q", tc.Bound)
		got, err := UnbindFS(tc.Bound)
		if tc.Error {
			t.Log(err)
			if err == nil {
				t.Error("expected error, got nil")
			}
			continue
		}
		if err != nil {
			t.Error(err)
		}
		if want := tc.WFN; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}

func TestURIUnbinding(t *testing.T) {
	// This table is made the URI unbinding examples in the standards document.
	tt := []struct {
		WFN   WFN
		Bound string
		Error bool
	}{
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "microsoft"},
				{Kind: ValueSet, V: "internet_explorer"},
				{Kind: ValueSet, V: `8\.0\.6001`},
				{Kind: ValueSet, V: "beta"},
				{Kind: ValueAny},
				{},
				{},
				{},
				{Kind: ValueAny},
				{},
			}},
			Bound: `cpe:/a:microsoft:internet_explorer:8.0.6001:beta`},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.\*",update="sp\?",edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "microsoft"},
				{Kind: ValueSet, V: "internet_explorer"},
				{Kind: ValueSet, V: `8\.\*`},
				{Kind: ValueSet, V: `sp\?`},
				{Kind: ValueAny},
				{},
				{},
				{},
				{Kind: ValueAny},
				{},
			}},
			Bound: `cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f`},
		// wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.*",update="sp?",edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "microsoft"},
				{Kind: ValueSet, V: "internet_explorer"},
				{Kind: ValueSet, V: `8\.*`},
				{Kind: ValueSet, V: "sp?"},
				{Kind: ValueAny},
				{},
				{},
				{},
				{Kind: ValueAny},
				{},
			}},
			Bound: `cpe:/a:microsoft:internet_explorer:8.%02:sp%01`},
		// wfn:[part="a",vendor="hp",product="insight_diagnostics",version="7\.4\.0\.1570",update=ANY,edition=ANY,sw_edition="online",target_sw="win2003",target_hw="x64",other=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "hp"},
				{Kind: ValueSet, V: "insight_diagnostics"},
				{Kind: ValueSet, V: `7\.4\.0\.1570`},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueSet, V: "online"},
				{Kind: ValueSet, V: "win2003"},
				{Kind: ValueSet, V: "x64"},
				{Kind: ValueAny},
				{Kind: ValueAny},
			}},
			Bound: `cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~`},
		// wfn:[part="a",vendor="hp",product="openview_network_manager",version="7\.51",update=NA,edition=ANY,sw_edition=ANY,target_sw="linux",target_HW=ANY,other=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: "hp"},
				{Kind: ValueSet, V: "openview_network_manager"},
				{Kind: ValueSet, V: `7\.51`},
				{Kind: ValueNA},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueSet, V: "linux"},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueAny},
			}},
			Bound: `cpe:/a:hp:openview_network_manager:7.51:-:~~~linux~~`},
		// An error is raised when this URI is unbound, because it contains an illegal percent-encoded form,"%07".
		{
			Bound: `cpe:/a:foo%5cbar:big%24money_2010%07:::~~special~ipod_touch~80gb~`,
			Error: true,
		},
		// wfn:[part="a",vendor="foo\~bar",product="big\~money_2010",version=ANY,update=ANY,edition=ANY,language=ANY]
		{
			WFN: WFN{Attr: [NumAttr]Value{
				{Kind: ValueSet, V: "a"},
				{Kind: ValueSet, V: `foo\~bar`},
				{Kind: ValueSet, V: `big\~money_2010`},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{Kind: ValueAny},
				{},
				{},
				{},
				{Kind: ValueAny},
				{},
			}},
			Bound: `cpe:/a:foo~bar:big%7emoney_2010`},
		// An error is raised when this URI is unbound, because it contains a special character ("%02") embedded within a valuestring.
		{
			Bound: `cpe:/a:foo:bar:12.%02.1234`,
			Error: true,
		},
	}
	for _, tc := range tt {
		t.Logf("%q", tc.Bound)
		got, err := UnbindURI(tc.Bound)
		if tc.Error {
			t.Log(err)
			if err == nil {
				t.Error("expected error, got nil")
			}
			continue
		}
		if err != nil {
			t.Error(err)
		}
		if want := tc.WFN; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
