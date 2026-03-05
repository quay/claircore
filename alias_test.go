package claircore

import (
	"fmt"
	"testing"
	"unique"
)

func alias(space, name string) Alias {
	return Alias{
		Space: unique.Make(space),
		Name:  name,
	}
}

func ExampleAlias_uri() {
	fmt.Println(alias("https://example.com/", "CVE-2014-0160"))
	// Output:
	// https://example.com/#CVE-2014-0160
}

func ExampleAlias_cve() {
	fmt.Println(alias("CVE", "2014-0160"))
	// Output:
	// CVE-2014-0160
}

func ExampleAlias_Equal() {
	a, b := alias("CVE", "2014-0160"), alias("CVE", "2014-0160")
	fmt.Println("equal:", a.Equal(b))
	// Output:
	// equal: true
}

func TestAlias(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		t.Run("OK", func(t *testing.T) {
			a := Alias{Space: unique.Make("TEST"), Name: "1"}
			if got, want := a.Valid(), true; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("Zero", func(t *testing.T) {
			a := Alias{}
			if got, want := a.Valid(), false; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("MissingSpace", func(t *testing.T) {
			a := Alias{Name: "1"}
			if got, want := a.Valid(), false; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("EmptySpace", func(t *testing.T) {
			a := Alias{Space: unique.Make(""), Name: "1"}
			if got, want := a.Valid(), false; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("MissingName", func(t *testing.T) {
			a := Alias{Space: unique.Make("TEST")}
			if got, want := a.Valid(), false; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	})
}
