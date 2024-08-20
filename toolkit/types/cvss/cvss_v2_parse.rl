package cvss

import "fmt"

// UnmarshalText implements [encoding.TextUnmarshaler].
func (v *V2) UnmarshalText(data []byte) error  {
	var m V2Metric
	var mi, vi int
	var set uint
	cs, p, pe, eof := 0, 0, len(data), len(data)
%%{
machine v2;

action value_start { vi = p }
action mark_value {
	switch s := string(data[vi:p]); {
	case m == V2ReportConfidence && s == "UR":
		v.mv[m] = 'u'
	case m == V2CollateralDamagePotential && s == "LM":
		v.mv[m] = 'l'
	case m == V2CollateralDamagePotential && s == "ND":
		v.mv[m] = 'X'
	case m == V2TargetDistribution && s == "ND":
		v.mv[m] = 'X'
	default:
		v.mv[m] = s[0]
	}
}
action metric_start { mi = p }
action mark_metric {
	m = v2Rev[string(data[mi:p])]
	x := uint(1 << uint(m))
	if (set & x) != 0 {
		return fmt.Errorf("cvss v2: %w: duplicated metric: %s\u2192%s\u2190%s",
			ErrMalformedVector,
			string(data[:mi]), string(data[mi:p]), string(data[p:]))
	}
	set |= x
}

av  = ( "AV"  >metric_start %mark_metric) ":" ( [LAN]                        >value_start %mark_value);
ac  = ( "AC"  >metric_start %mark_metric) ":" ( [HML]                        >value_start %mark_value);
au  = ( "Au"  >metric_start %mark_metric) ":" ( [MSN]                        >value_start %mark_value);
c   = ( "C"   >metric_start %mark_metric) ":" ( [NPC]                        >value_start %mark_value);
i   = ( "I"   >metric_start %mark_metric) ":" ( [NPC]                        >value_start %mark_value);
a   = ( "A"   >metric_start %mark_metric) ":" ( [NPC]                        >value_start %mark_value);
e   = ( "E"   >metric_start %mark_metric) ":" ( ("U"|"POC"|"F"|"H"|"ND")     >value_start %mark_value);
rl  = ( "RL"  >metric_start %mark_metric) ":" ( ("OF"|"TF"|"W"|"U"|"ND")     >value_start %mark_value);
rc  = ( "RC"  >metric_start %mark_metric) ":" ( ("UC"|"UR"|"C"|"ND")         >value_start %mark_value);
cdp = ( "CDP" >metric_start %mark_metric) ":" ( ("N"|"L"|"LM"|"MH"|"H"|"ND") >value_start %mark_value);
td  = ( "TD"  >metric_start %mark_metric) ":" ( ("N"|"L"|"M"|"H"|"ND")       >value_start %mark_value);
cr  = ( "CR"  >metric_start %mark_metric) ":" ( ("L"|"M"|"H"|"ND")           >value_start %mark_value);
ir  = ( "IR"  >metric_start %mark_metric) ":" ( ("L"|"M"|"H"|"ND")           >value_start %mark_value);
ar  = ( "AR"  >metric_start %mark_metric) ":" ( ("L"|"M"|"H"|"ND")           >value_start %mark_value);

base = av "/" ac "/" au "/" c "/" i "/" a;
temporal = e "/" rl "/" rc;
environmental = cdp "/" td "/" cr "/" ir "/" ar;

main := ( base ("/" temporal)? ("/" environmental)? ) $err {
	if p == eof {
		return fmt.Errorf("cvss v2: %w: too short", ErrMalformedVector)
	}
	return fmt.Errorf("cvss v2: %w: unexpected character #%d: %s\u2192%c\u2190%s",
		ErrMalformedVector,
		p+1, string(data[:p]), fc, string(data[p+1:]))
};

write init;
write exec;
}%%
	if p != eof {
		return fmt.Errorf("cvss v2: %w: unexpected character #%d: %s\u2192%c\u2190%s",
			ErrMalformedVector,
			p+1, string(data[:p]), data[p], string(data[p+1:]))
	}
	for m, b := range v.mv[:V2Availability+1] { // range inclusive
		if b == 0 {
			return fmt.Errorf("cvss v2: %w: missing metric: %q", ErrMalformedVector, V2Metric(m).String())
		}
	}
	for _, x := range []struct{
		Name string
		Set uint
	}{
		{"Temporal", uint(1<<V2Exploitability | 1<<V2RemediationLevel | 1<<V2ReportConfidence)},
		{"Environmental", uint(1<<V2CollateralDamagePotential | 1<<V2TargetDistribution | 1<<V2ConfidentialityRequirement | 1<<V2IntegrityRequirement | 1<<V2AvailabilityRequirement)},
	} {
		if g := set&x.Set; g != 0 && g != x.Set {
			return fmt.Errorf("cvss v2: %w: missing %q group metrics", ErrMalformedVector, x.Name)
		}
	}
	return nil
}

%% write data;
