package urn

import (
	"strings"
	"testing"
)

func TestCompliance(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		t.Run("Basic", parseOK(`urn:test:test`))
		t.Run("NID", parseOK(`urn:test-T-0123456789:test`))
		t.Run("NSS", parseOK(`urn:test:Test-0123456789()+,-.:=@;$_!*'`))
	})
	t.Run("Invalid", func(t *testing.T) {
		t.Run("NID", func(t *testing.T) {
			t.Run("TooLong", parseErr(`urn:`+strings.Repeat("a", 33)+`:test`))
			t.Run("BadChars", parseErr(`urn:test//notOK:test`))
			t.Run("None", parseErr(`urn::test`))
			t.Run("HyphenStart", parseErr(`urn:-nid:test`))
			t.Run("HyphenEnd", parseErr(`urn:nid-:test`))
		})
		t.Run("NSS", func(t *testing.T) {
			t.Run("BadChar", parseErr("urn:test:null\x00null"))
		})
	})
	t.Run("Equivalence", func(t *testing.T) {
		// These test cases are ported out of the RFC.
		t.Run("CaseInsensitive", allEqual(`urn:example:a123,z456`, `URN:example:a123,z456`, `urn:EXAMPLE:a123,z456`))
		t.Run("Component", allEqual(`urn:example:a123,z456`, `urn:example:a123,z456?+abc`, `urn:example:a123,z456?=xyz`, `urn:example:a123,z456#789`))
		t.Run("NSS", allNotEqual(`urn:example:a123,z456`, `urn:example:a123,z456/foo`, `urn:example:a123,z456/bar`, `urn:example:a123,z456/baz`))
		t.Run("PercentDecoding", func(t *testing.T) {
			p := []string{`urn:example:a123%2Cz456`, `URN:EXAMPLE:a123%2cz456`}
			allEqual(p...)(t)
			for _, p := range p {
				allNotEqual(`urn:example:a123,z456`, p)(t)
			}
		})
		t.Run("CaseSensitive", allNotEqual(`urn:example:a123,z456`, `urn:example:A123,z456`, `urn:example:a123,Z456`))
		t.Run("PercentEncoding", func(t *testing.T) {
			allNotEqual(`urn:example:a123,z456`, `urn:example:%D0%B0123,z456`)(t)
			allEqual(`urn:example:а123,z456`, `urn:example:%D0%B0123,z456`)(t) // NB that's \u0430 CYRILLIC SMALL LETTER A
		})
	})
}

func parseOK(s string) func(*testing.T) {
	u, err := Parse(s)
	return func(t *testing.T) {
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.R(); err != nil {
			t.Error(err)
		}
		if _, err := u.Q(); err != nil {
			t.Error(err)
		}
	}
}
func parseErr(s string) func(*testing.T) {
	u, err := Parse(s)
	return func(t *testing.T) {
		t.Log(err)
		if err != nil {
			// OK
			return
		}
		if _, err := u.R(); err == nil {
			t.Fail()
		}
		if _, err := u.Q(); err == nil {
			t.Fail()
		}
	}
}
func allEqual(s ...string) func(*testing.T) {
	var err error
	u := make([]URN, len(s))
	for i, s := range s {
		u[i], err = Parse(s)
		if err != nil {
			break
		}
	}
	return func(t *testing.T) {
		if err != nil {
			t.Fatal(err)
		}
		for i := range u {
			for j := range u {
				if !(&u[i]).Equal(&u[j]) {
					t.Errorf("%v != %v", &u[i], &u[j])
				}
			}
		}
	}
}
func allNotEqual(s ...string) func(*testing.T) {
	var err error
	u := make([]URN, len(s))
	for i, s := range s {
		u[i], err = Parse(s)
		if err != nil {
			break
		}
	}
	return func(t *testing.T) {
		if err != nil {
			t.Fatal(err)
		}
		for i := range u {
			for j := range u {
				if i != j && (&u[i]).Equal(&u[j]) {
					t.Errorf("%v == %v", &u[i], &u[j])
				}
			}
		}
	}
}
