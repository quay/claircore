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

func BenchmarkUnbindFS(b *testing.B) {
	inner := func(in string) func(*testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				out, err := UnbindFS(in)
				if err != nil {
					b.Error(err)
				}
				_ = out
			}
		}
	}
	b.Run("Simple", inner(cpeFS))
	b.Run("Escape", inner(cpeEscapeFS))
}
