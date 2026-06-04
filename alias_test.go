package claircore

import (
	"encoding/json"
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

func ExampleAlias_uri_slash() {
	fmt.Println(alias("https://example.com/", "CVE-2014-0160"))
	// Output:
	// https://example.com/CVE-2014-0160
}

func ExampleAlias_uri_anchor() {
	fmt.Println(alias("https://example.com/cve", "CVE-2014-0160"))
	// Output:
	// https://example.com/cve#CVE-2014-0160
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

	t.Run("JSON", func(t *testing.T) {
		a := Alias{Space: unique.Make("CVE"), Name: "2024-24786"}
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"space":"CVE","name":"2024-24786"}`
		if got := string(data); got != want {
			t.Fatalf("marshal: got %s, want %s", got, want)
		}

		var b Alias
		if err := json.Unmarshal(data, &b); err != nil {
			t.Fatal(err)
		}
		if !a.Equal(b) {
			t.Errorf("unmarshal: got %v, want %v", b, a)
		}
	})

	t.Run("JSONZero", func(t *testing.T) {
		a := Alias{}
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"space":"","name":""}`
		if got := string(data); got != want {
			t.Errorf("marshal: got %s, want %s", got, want)
		}

		var b Alias
		if err := json.Unmarshal(data, &b); err != nil {
			t.Fatal(err)
		}
		if b.Valid() {
			t.Errorf("unmarshal zero: expected invalid alias, got valid: %v", b)
		}
	})
}
