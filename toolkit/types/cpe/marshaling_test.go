package cpe

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMarshal(t *testing.T) {
	t.Parallel()
	var names = []string{
		`cpe:2.3:a:foo\\bar:big\$money:2010:*:*:*:special:ipod_touch:80gb:*`,
		`cpe:2.3:a:foo\\bar:big\$money_2010:*:*:*:*:special:ipod_touch:80gb:*`,
		`cpe:2.3:a:hp:insight:7.4.0.1570:-:*:*:online:win2003:x64:*`,
		`cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*`,
		`cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*`,
		`cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*`,
		`cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*`,
		`cpe:2.3:a:microsoft:internet_explorer:8.\*:sp?:*:*:*:*:*:*`,
	}
	t.Run("JSON", func(t *testing.T) {
		for _, n := range names {
			var wfn WFN
			if err := wfn.UnmarshalText([]byte(n)); err != nil {
				t.Error(err)
			}
			b, err := wfn.MarshalText()
			if err != nil {
				t.Error(err)
			}
			if got, want := string(b), n; got != want {
				t.Error(cmp.Diff(got, want))
			}
		}
		t.Run("Unset", func(t *testing.T) {
			b, err := new(WFN).MarshalText()
			if err != nil {
				t.Error(err)
			}
			if b == nil {
				t.Error("return value unexpectedly nil")
			}
			if len(b) != 0 {
				t.Error("return value unexpectedly long")
			}
		})
		t.Run("Nil", func(t *testing.T) {
			if err := new(WFN).UnmarshalText(nil); err != nil {
				t.Error(err)
			}
		})
		t.Run("Error", func(t *testing.T) {
			var wfn WFN
			wfn.Attr[Part].Kind = ValueSet
			wfn.Attr[Part].V = "x"
			b, err := wfn.MarshalText()
			t.Log(err)
			if err == nil {
				t.Error("return error unexpectedly nil")
			}
			if b != nil {
				t.Error("return value unexpectedly not-nil")
			}
		})
	})
	t.Run("SQL", func(t *testing.T) {
		for _, n := range names {
			var wfn WFN
			if err := wfn.Scan(n); err != nil {
				t.Error(err)
			}
			if err := new(WFN).Scan([]byte(n)); err != nil {
				t.Error(err)
			}
			v, err := wfn.Value()
			if err != nil {
				t.Error(err)
			}
			if got, want := v.(string), n; got != want {
				t.Error(cmp.Diff(got, want))
			}
		}
		t.Run("Unset", func(t *testing.T) {
			v, err := new(WFN).Value()
			if err != nil {
				t.Error(err)
			}
			if v == nil {
				t.Error("return value unexpectedly nil")
			}
			if len(v.(string)) != 0 {
				t.Error("return value unexpectedly long")
			}
		})
		t.Run("Error", func(t *testing.T) {
			var wfn WFN
			wfn.Attr[Part].Kind = ValueSet
			wfn.Attr[Part].V = "x"
			b, err := wfn.Value()
			t.Log(err)
			if err == nil {
				t.Error("return error unexpectedly nil")
			}
			if b != nil {
				t.Error("return value unexpectedly not-nil")
			}
		})
		t.Run("Other", func(t *testing.T) {
			err := new(WFN).Scan(nil)
			t.Log(err)
			if err == nil {
				t.Error("return value unexpectedly nil")
			}
		})
	})
	t.Run("Stringer", func(t *testing.T) {
		for _, n := range names {
			var wfn WFN
			if err := wfn.UnmarshalText([]byte(n)); err != nil {
				t.Error(err)
			}
			if got, want := wfn.String(), n; got != want {
				t.Error(cmp.Diff(got, want))
			}
		}
	})
}
