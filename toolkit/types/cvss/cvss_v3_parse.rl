package cvss

import "fmt"

// UnmarshalText implements [encoding.TextUnmarshaler].
func (v *V3) UnmarshalText(data []byte) error  {
	var m V3Metric
	var mi int
	var set uint
	cs, p, pe, eof := 0, 0, len(data), len(data)
%%{
machine v3;

action mark_minor { v.ver = int8(fc - byte('0')) }
action mark_value { v.mv[m] = fc }
action metric_start { mi = p }
action mark_metric {
	m = v3Rev[string(data[mi:p])]
	x := uint(1 << uint(m))
	if (set & x) != 0 {
		return fmt.Errorf("cvss v3: %w: duplicated metric: %s\u2192%s\u2190%s",
			ErrMalformedVector,
			string(data[:mi]), string(data[mi:p]), string(data[p:]))
	}
	set |= x
}

av  = "/" ( "AV"  >metric_start %mark_metric) ":" [NALP]  >mark_value;
ac  = "/" ( "AC"  >metric_start %mark_metric) ":" [LH]    >mark_value;
pr  = "/" ( "PR"  >metric_start %mark_metric) ":" [NLH]   >mark_value;
ui  = "/" ( "UI"  >metric_start %mark_metric) ":" [NR]    >mark_value;
s   = "/" ( "S"   >metric_start %mark_metric) ":" [UC]    >mark_value;
c   = "/" ( "C"   >metric_start %mark_metric) ":" [HLN]   >mark_value;
i   = "/" ( "I"   >metric_start %mark_metric) ":" [HLN]   >mark_value;
a   = "/" ( "A"   >metric_start %mark_metric) ":" [HLN]   >mark_value;
e   = "/" ( "E"   >metric_start %mark_metric) ":" [XHFPU] >mark_value;
rl  = "/" ( "RL"  >metric_start %mark_metric) ":" [XUWTO] >mark_value;
rc  = "/" ( "RC"  >metric_start %mark_metric) ":" [XCRU]  >mark_value;
cr  = "/" ( "CR"  >metric_start %mark_metric) ":" [XHML]  >mark_value;
ir  = "/" ( "IR"  >metric_start %mark_metric) ":" [XHML]  >mark_value;
ar  = "/" ( "AR"  >metric_start %mark_metric) ":" [XHML]  >mark_value;
mav = "/" ( "MAV" >metric_start %mark_metric) ":" [XNALP] >mark_value;
mac = "/" ( "MAC" >metric_start %mark_metric) ":" [XLH]   >mark_value;
mpr = "/" ( "MPR" >metric_start %mark_metric) ":" [XNLH]  >mark_value;
mui = "/" ( "MUI" >metric_start %mark_metric) ":" [XNR]   >mark_value;
ms  = "/" ( "MS"  >metric_start %mark_metric) ":" [XUC]   >mark_value;
mc  = "/" ( "MC"  >metric_start %mark_metric) ":" [XNLH]  >mark_value;
mi  = "/" ( "MI"  >metric_start %mark_metric) ":" [XNLH]  >mark_value;
ma  = "/" ( "MA"  >metric_start %mark_metric) ":" [XNLH]  >mark_value;

main := ( "CVSS:3." ([01] >mark_minor)
	( av | ac | pr | ui | s | c | i | a |
	   e | rl | rc |
	  cr | ir | ar | mav | mac | mpr | mui | ms | mc | mi | ma
	)+ ) $err {
	if p == eof {
		return fmt.Errorf("cvss v3: %w: too short", ErrMalformedVector)
	}
	return fmt.Errorf("cvss v3: %w: unexpected character #%d: %s\u2192%c\u2190%s",
		ErrMalformedVector,
		p+1, string(data[:p]), fc, string(data[p+1:]))
};

write init;
write exec;
}%%
	if p != eof {
		return fmt.Errorf("cvss v3: %w: unexpected character #%d: %s\u2192%c\u2190%s",
			ErrMalformedVector,
			p+1, string(data[:p]), data[p], string(data[p+1:]))
	}
	for m, b := range v.mv[:V3Availability+1] { // range inclusive
		if b == 0 {
			return fmt.Errorf("cvss v3: %w: missing metric: %q", ErrMalformedVector, V3Metric(m).String())
		}
	}
	return nil
}

%% write data;
