package cpe

import (
	"strings"
)

// Compare implements the pairwise CPE comparison algorithm as defined by
// the CPE Name Matching spec: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
func Compare(src, tgt WFN) Relations {
	var m [NumAttr]Relation
	for i := 0; i < NumAttr; i++ {
		sv, tv := src.Attr[i], tgt.Attr[i]
		// This encodes table 6-2 of the matching spec.
		if tv.Kind == ValueSet && hasWildcard(tv.V) {
			m[i] = Relation(0)
			continue
		}
		switch sv.Kind {
		case ValueAny:
			switch tv.Kind {
			case ValueAny:
				m[i] = Equal
			case ValueNA:
				m[i] = Superset
			case ValueSet:
				m[i] = Superset
			}
		case ValueNA:
			switch tv.Kind {
			case ValueAny:
				m[i] = Subset
			case ValueNA:
				m[i] = Equal
			case ValueSet:
				m[i] = Disjoint
			}
		case ValueSet:
			if hasWildcard(sv.V) {
				switch tv.Kind {
				case ValueAny:
					m[i] = Subset
				case ValueNA:
					m[i] = Disjoint
				case ValueSet:
					// case insensitive glob compare
					if !patCompare(sv.V, tv.V) {
						m[i] = Disjoint
					}
					m[i] = Superset
				}
				break
			}
			switch tv.Kind {
			case ValueAny:
				m[i] = Subset
			case ValueNA:
				m[i] = Disjoint
			case ValueSet:
				if strings.EqualFold(sv.V, tv.V) {
					m[i] = Equal
					break
				}
				m[i] = Disjoint
			}
		case ValueUnset:
			if tv.Kind == ValueUnset {
				m[i] = Equal
				break
			}
			m[i] = Disjoint
		}
	}
	return m
}

func hasWildcard(s string) bool {
	return strings.ContainsAny(s, "*?")
}

// PatCompare takes in a source and target string and runs an implementation of the
// case-insensitive string match, interpreting the source string as a glob-like pattern.
func patCompare(s, t string) bool {
	s, t = strings.ToLower(s), strings.ToLower(t)
	var pref, suf int
	switch {
	case strings.HasPrefix(s, "*"):
		pref = -1
		s = s[1:]
	case strings.HasPrefix(s, "?"):
		s = strings.TrimLeftFunc(s, func(r rune) (ok bool) {
			ok = r == '?'
			if ok {
				pref++
			}
			return ok
		})
	default:
	}
	switch {
	case strings.HasSuffix(s, "*"):
		suf = -1
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "?"):
		s = strings.TrimRightFunc(s, func(r rune) (ok bool) {
			ok = r == '?'
			if ok {
				suf++
			}
			return ok
		})
	default:
	}
	idx := strings.Index(t, s)
	if idx == -1 {
		return false
	}
	switch ct := idx; {
	case pref == -1: // OK
	case ct == pref: // OK
	default:
		return false
	}
	switch ct := len(t) - idx + len(s); {
	case suf == -1: // OK
	case ct == suf: // OK
	default:
		return false
	}
	return true
}

// Relations is the pairwise comparison of a source CPE match expression and a target CPE.
type Relations [NumAttr]Relation

// IsSuperset reports whether the source and target are a "non-proper" superset.
func (rs Relations) IsSuperset() bool {
	for i := 0; i < NumAttr; i++ {
		if r := rs[i]; r != Equal && r != Superset {
			return false
		}
	}
	return true
}

// IsSubset reports whether the source and target are a "non-proper" subset.
func (rs Relations) IsSubset() bool {
	for i := 0; i < NumAttr; i++ {
		if r := rs[i]; r != Equal && r != Subset {
			return false
		}
	}
	return true
}

// IsEqual reports whether the source and target are equal.
func (rs Relations) IsEqual() bool {
	for i := 0; i < NumAttr; i++ {
		if rs[i] != Equal {
			return false
		}
	}
	return true
}

// IsDisjoint reports whether the source and target are disjoint or mutually exclusive.
func (rs Relations) IsDisjoint() bool {
	for i := 0; i < NumAttr; i++ {
		if rs[i] == Disjoint {
			return true
		}
	}
	return false
}

// Relation indicates the relation of two WFN attributes.
type Relation uint

//go:generate stringer -type Relation -linecomment

// These are the possible relations between WFNs and their components.
//
// The super- and sub-sets indicate the conventional sense, meaning a set is
// equal to itself and also a superset and subset of itself.
const (
	_        Relation = iota // invalid
	Superset                 //⊃
	Subset                   //⊂
	Equal                    //=
	Disjoint                 //≠
)
