package urn

import "errors"
import "fmt"

%% machine urn;
%% write data;

func parse(out *URN, data string) (err error) {
	var p, b, cs int
	pe := len(data)
	eof := len(data)
	pct := false

%%{
	action err_scheme {
		err = fmt.Errorf("invalid scheme: %q", data[:p])
		fbreak;
	}
	action err_nid {
		err = fmt.Errorf("invalid nid: %q", data[b:p])
		fbreak;
	}
	action err_nid_toolong {
		err = errors.New("invalid nid: too long")
		fbreak;
	}
	action err_nid_char {
		err = fmt.Errorf("invalid nid: bad char at pos %d: %+q", p, data[p])
		fbreak;
	}
	action err_nss {
		err = fmt.Errorf("invalid nss: %q", data[b:p])
		fbreak;
	}

	action mark {
		b = p
		pct = false
	}
	action set_pct {
		pct = true
	}

	action set_nid {
		out.setNID(data[b:p])
	}
	action set_nss {
		out.setNSS(data[b:p])
	}
	action set_rc {
		out.r = data[b:p]
	}
	action set_qc {
		out.q = data[b:p]
	}
	action set_fc {
		out.f = data[b:p]
	}

	sub_delims = [!$&'()*+,;=];
	pct_encoded = ('%' xdigit{2}) >set_pct;
	unreserved = alnum | [._~] | '-';
	pchar = unreserved | pct_encoded | sub_delims | [:@];
	query = pchar ( pchar | [/?] )*;
	NSS = (pchar (pchar | '/')*) >mark %set_nss @err(err_nss);
	ldh = (alnum | '-') @err(err_nid_char);
	NID = (alnum @err(err_nid_char) ldh{,30} alnum @err(err_nid_char)) >mark %set_nid @err(err_nid);
	assigned_name = ([Uu][Rr][Nn] ':') %mark @err(err_scheme) (NID ':' @err(err_nid_toolong)) NSS;
	f_component = query* >mark %set_fc;
	rq_components = ('?+' query* >mark %set_rc)? ('?=' query* >mark %set_qc)?;

	main := assigned_name rq_components? ('#' f_component)?;

	write init;
	write exec;
}%%

	if err != nil {
		return err
	}
	if p != eof {
		return errors.New("invalid nss")
	}
	_=pct
	return nil
}
