package cvss

import "fmt"

// UnmarshalText implements [encoding.TextUnmarshaler].
func (v *V4) UnmarshalText(data []byte) error  {
	var m V4Metric
	var mi int
	cs, p, pe, eof := 0, 0, len(data), len(data)
%%{
machine v4;

action mark_value { v.mv[m] = fc }
action metric_start { mi = p }
action mark_metric { m = v4Rev[string(data[mi:p])] }

av  = "/" ( "AV"  >metric_start %mark_metric) ":" [NALP]                              >mark_value;
ac  = "/" ( "AC"  >metric_start %mark_metric) ":" [LH]                                >mark_value;
at  = "/" ( "AT"  >metric_start %mark_metric) ":" [NP]                                >mark_value;
pr  = "/" ( "PR"  >metric_start %mark_metric) ":" [NLH]                               >mark_value;
ui  = "/" ( "UI"  >metric_start %mark_metric) ":" [NPA]                               >mark_value;
vc  = "/" ( "VC"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
vi  = "/" ( "VI"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
va  = "/" ( "VA"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
sc  = "/" ( "SC"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
si  = "/" ( "SI"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
sa  = "/" ( "SA"  >metric_start %mark_metric) ":" [HLN]                               >mark_value;
e   = "/" ( "E"   >metric_start %mark_metric) ":" [XAPU]                              >mark_value;
cr  = "/" ( "CR"  >metric_start %mark_metric) ":" [XHML]                              >mark_value;
ir  = "/" ( "IR"  >metric_start %mark_metric) ":" [XHML]                              >mark_value;
ar  = "/" ( "AR"  >metric_start %mark_metric) ":" [XHML]                              >mark_value;
mav = "/" ( "MAV" >metric_start %mark_metric) ":" [XNALP]                             >mark_value;
mac = "/" ( "MAC" >metric_start %mark_metric) ":" [XLH]                               >mark_value;
mat = "/" ( "MAT" >metric_start %mark_metric) ":" [XNP]                               >mark_value;
mpr = "/" ( "MPR" >metric_start %mark_metric) ":" [XNLH]                              >mark_value;
mui = "/" ( "MUI" >metric_start %mark_metric) ":" [XNPA]                              >mark_value;
mvc = "/" ( "MVC" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
mvi = "/" ( "MVI" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
mva = "/" ( "MVA" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
msc = "/" ( "MSC" >metric_start %mark_metric) ":" [XHLN]                              >mark_value;
msi = "/" ( "MSI" >metric_start %mark_metric) ":" [XHLNS]                             >mark_value;
msa = "/" ( "MSA" >metric_start %mark_metric) ":" [XHLNS]                             >mark_value;
s   = "/" ( "S"   >metric_start %mark_metric) ":" [XNP]                               >mark_value;
au  = "/" ( "AU"  >metric_start %mark_metric) ":" [XNY]                               >mark_value;
r   = "/" ( "R"   >metric_start %mark_metric) ":" [XAUI]                              >mark_value;
v   = "/" ( "V"   >metric_start %mark_metric) ":" [XDC]                               >mark_value;
re  = "/" ( "RE"  >metric_start %mark_metric) ":" [XLMH]                              >mark_value;
u   = "/" ( "U"   >metric_start %mark_metric) ":" ("X"|"Clear"|"Green"|"Amber"|"Red") >mark_value;

base = av  ac  at  pr  ui  vc  vi  va  sc  si  sa;
threat = e?;
environmental = cr? ir? ar? mav? mac? mat? mpr? mui? mvc? mvi? mva? msc? msi? msa?;
supplemental = s? au? r? v? re? u?;

# In the future, this will probably need to branch based on the minor version.
main := ( "CVSS:4.0" base threat environmental supplemental ) $err {
	if p == eof {
		return fmt.Errorf("cvss v4: %w: too short", ErrMalformedVector)
	}
	return fmt.Errorf("cvss v4: %w: unexpected character #%d: %s\u2192%c\u2190%s",
		ErrMalformedVector,
		p+1, string(data[:p]), fc, string(data[p+1:]))
};

write init;
write exec;
}%%
	if p != eof {
		return fmt.Errorf("cvss v4: %w: unexpected character #%d: %s\u2192%c\u2190%s",
			ErrMalformedVector,
			p+1, string(data[:p]), data[p], string(data[p+1:]))
	}
	for m, b := range v.mv[:V4SubsequentSystemAvailability+1] { // range inclusive
		if b == 0 {
			return fmt.Errorf("cvss v4: %w: missing metric: %q", ErrMalformedVector, V4Metric(m).String())
		}
	}
	return nil
}

%% write data;
