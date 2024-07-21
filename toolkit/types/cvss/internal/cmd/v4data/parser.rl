package main

import (
"fmt"
"github.com/quay/claircore/toolkit/types/cvss"
)

// Copied out of the cvss package. Accurate for 4.0.
const numV4Metrics = 32

// MustParseV4Frag is a helper for constructing score data in the cvss package.
//
// This is very close to the "v4" machine, but has no completeness requirements
// and allows some invalid values in the S[IA] metrics.
// See the BUG note in the cvss package for details.
func mustParseV4Frag(in string) []byte {
	var v [numV4Metrics]byte
	var m cvss.V4Metric
	var mi int
	data := []byte(in)
	cs, p, pe, eof := 0, 0, len(data), len(data)
%%{
machine v4frag;

action mark_value { v[m] = fc }
action metric_start { mi = p }
action mark_metric { m = v4Rev[string(data[mi:p])] }

av  = ( "AV"  >metric_start %mark_metric) ":" [NALP]                              >mark_value;
ac  = ( "AC"  >metric_start %mark_metric) ":" [LH]                                >mark_value;
at  = ( "AT"  >metric_start %mark_metric) ":" [NP]                                >mark_value;
pr  = ( "PR"  >metric_start %mark_metric) ":" [NLH]                               >mark_value;
ui  = ( "UI"  >metric_start %mark_metric) ":" [NPA]                               >mark_value;
vc  = ( "VC"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
vi  = ( "VI"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
va  = ( "VA"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
sc  = ( "SC"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
si  = ( "SI"  >metric_start %mark_metric) ":" [HLNS]                              >mark_value;
sa  = ( "SA"  >metric_start %mark_metric) ":" [HLNS]                              >mark_value;
e   = ( "E"   >metric_start %mark_metric) ":" [XAPU]                              >mark_value;
cr  = ( "CR"  >metric_start %mark_metric) ":" [XHML]                              >mark_value;
ir  = ( "IR"  >metric_start %mark_metric) ":" [XHML]                              >mark_value;
ar  = ( "AR"  >metric_start %mark_metric) ":" [XHML]                              >mark_value;
mav = ( "MAV" >metric_start %mark_metric) ":" [XNALP]                             >mark_value;
mac = ( "MAC" >metric_start %mark_metric) ":" [XLH]                               >mark_value;
mat = ( "MAT" >metric_start %mark_metric) ":" [XNP]                               >mark_value;
mpr = ( "MPR" >metric_start %mark_metric) ":" [XNLH]                              >mark_value;
mui = ( "MUI" >metric_start %mark_metric) ":" [XNPA]                              >mark_value;
mvc = ( "MVC" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
mvi = ( "MVI" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
mva = ( "MVA" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
msc = ( "MSC" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
msi = ( "MSI" >metric_start %mark_metric) ":" [XHLNS]                             >mark_value;
msa = ( "MSA" >metric_start %mark_metric) ":" [XHLNS]                             >mark_value;
s   = ( "S"   >metric_start %mark_metric) ":" [XNP]                               >mark_value;
au  = ( "AU"  >metric_start %mark_metric) ":" [XNY]                               >mark_value;
r   = ( "R"   >metric_start %mark_metric) ":" [XAUI]                              >mark_value;
v   = ( "V"   >metric_start %mark_metric) ":" [XDC]                               >mark_value;
re  = ( "RE"  >metric_start %mark_metric) ":" [XLMH]                              >mark_value;
u   = ( "U"   >metric_start %mark_metric) ":" ("X"|"Clear"|"Green"|"Amber"|"Red") >mark_value;

metric =
	av| ac| at| pr| ui| vc| vi| va| sc| si| sa|
	e|
	cr| ir| ar| mav| mac| mat| mpr| mui| mvc| mvi| mva| msc| msi| msa|
	s| au| r| v| re| u;

main := ( metric ( "/" metric )* ) $err {
	if p == eof {
		panic(fmt.Errorf("cvss v4: %w: %q: too short", cvss.ErrMalformedVector, in))
	}
	panic(fmt.Errorf("cvss v4: %w: unexpected character #%d: %s\u2192%c\u2190%s",
		cvss.ErrMalformedVector,
		p+1, string(data[:p]), fc, string(data[p+1:])))
};

write init;
write exec;
}%%
	if p != eof {
		panic(fmt.Errorf("cvss v4 fragment: %w: unexpected character #%d: %s\u2192%c\u2190%s",
			cvss.ErrMalformedVector,
			p+1, string(data[:p]), data[p], string(data[p+1:])))
	}

return v[:]
}

%% write data;
