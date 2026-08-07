package cpe

import (
	"fmt"
	"strings"
)

var fsReplacer = strings.NewReplacer(".", "\\.", "-", "\\-")

// UnmarshalFS unmarshals a "formatted string" bound CPE Name into the
// receiver.
func (w *WFN) UnmarshalFS(data string) error  {
	cs, p, pe, eof := 0, 0, len(data), len(data)

	a := 0
	i := 0
	needEsc := false
%%{
machine fs;

action mark_any    { w.Attr[a].Kind = ValueAny; }
action mark_na     { w.Attr[a].Kind = ValueNA; }
action next_attr   { a++; }
action mark_start  { i = p; }
action need_escape { needEsc = true; }
action mark_part   {
	w.Attr[a].Kind = ValueSet;
	w.Attr[a].V = data[p:p+1];
}
action mark_value  {
	w.Attr[a].Kind = ValueSet;
	s := data[i:p]
	if s == "\\-" {
		return fmt.Errorf("cpe: quoted hyphen MUST NOT be used by itself")
	}
	if needEsc {
		w.Attr[a].V = fsReplacer.Replace(s);
		needEsc = false
	} else {
		w.Attr[a].V = s;
	}
}

# This is a translation of the EBNF from the CPE Naming spec.
#
# The only definition that may need tweaking is the use of the builtin "punct"
# machine.

unreserved = alpha | digit | "_" | ("-" | ".") >need_escape;

spec2 = "*";
spec1 = "?";
special = spec1 | spec2;

escape = "\\";
quoted = escape (escape | special | punct);

logical = ("*" >mark_any | "-" >mark_na);

spec_chrs = spec1+ | spec2;
vstring = (spec_chrs? (unreserved | quoted)+ spec_chrs?) >mark_start %mark_value;
avstring = zlen | logical | (vstring - logical);

part       = [hoa] >mark_part | logical;
vendor     = avstring;
product    = avstring;
version    = avstring;
update     = avstring;
edition    = avstring;
lang       = avstring; # Not exactly right, but the spec is fuzzy on this.
sw_edition = avstring;
target_sw  = avstring;
target_hw  = avstring;
other      = avstring;

sep = ":" >next_attr;

component_list = part sep vendor sep product sep version sep update sep edition sep lang sep sw_edition sep target_sw sep target_hw sep other;

main := ( "cpe:2.3:" component_list ) $err {
	if p == eof {
		return fmt.Errorf("cpe: 2.3: too short")
	}
	return fmt.Errorf("cpe: 2.3: unexpected character #%d: %s\u2192%c\u2190%s",
		p+1, string(data[:p]), fc, string(data[p+1:]))
};

write init;
write exec;
}%%

	return nil
}

%% write data;
