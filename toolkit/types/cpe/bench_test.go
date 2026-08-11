package cpe

import (
	"testing"
)

const (
	// Test string where all value strings can be copied directly.
	cpeFS = `cpe:2.3:a:foo\\bar:big\$money_2010:*:*:*:*:special:ipod_touch:80gb:*`
	// Test string that needs additional escaping for the unbound form.
	cpeEscapeFS = `cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*`
)

func BenchmarkUnmarshalFS(b *testing.B) {
	inner := func(in string) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var out WFN
				if err := out.UnmarshalFS(in); err != nil {
					b.Error(err)
				}
			}
		}
	}
	b.Run("Simple", inner(cpeFS))
	b.Run("Escape", inner(cpeEscapeFS))
}

func BenchmarkBindFS(b *testing.B) {
	inner := func(in string) func(*testing.B) {
		return func(b *testing.B) {
			var out WFN
			if err := out.UnmarshalFS(in); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				s := out.BindFS()
				_ = s
			}
		}
	}
	b.Run("Simple", inner(cpeFS))
	b.Run("Escape", inner(cpeEscapeFS))
}
