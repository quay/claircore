package urn

// These functions are adapted out of the net/url package.
//
// URNs have slightly different rules.

// Copyright 2009 The Go Authors.

const upperhex = "0123456789ABCDEF"

// Escape only handles non-ASCII characters and leaves other validation to the
// parsers.
func escape(s string) string {
	ct := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > 0x7F {
			ct++
		}
	}

	if ct == 0 {
		return s
	}

	var buf [64]byte
	var t []byte

	required := len(s) + 2*ct
	if required <= len(buf) {
		t = buf[:required]
	} else {
		t = make([]byte, required)
	}

	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c > 0x7F:
			t[j] = '%'
			t[j+1] = upperhex[c>>4]
			t[j+2] = upperhex[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}
