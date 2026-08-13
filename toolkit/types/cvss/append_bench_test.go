package cvss

import (
	"math/rand/v2"
	"testing"
)

func BenchmarkAppend(b *testing.B) {
	b.Run("V2", benchAppendV2)
	b.Run("V3", benchAppendV3)
	b.Run("V4", benchAppendV4)
}

func benchAppendV4(b *testing.B) {
	buf := make([]byte, 0, 1024) // Is it cheating to oversize this?
	benchOne := func(b *testing.B, vec []byte) {
		b.Helper()
		b.Attr("input", string(vec))
		var v V4
		if err := v.UnmarshalText(vec); err != nil {
			b.Fatal(err)
		}
		var err error
		var x []byte
		b.ReportAllocs()

		for b.Loop() {
			x, err = v.AppendText(buf)
			if err != nil {
				b.Error(err)
			}
			_ = x
		}
	}

	b.Run("List", func(b *testing.B) {
		vecs := loadVectorList(b, `v4_roundtrip.list`)
		todo := make([][]byte, 10)
		for i := range todo {
			todo[i] = vecs[rand.N(len(vecs))]
		}
		for _, vec := range todo {
			b.Run("", func(b *testing.B) { benchOne(b, vec) })
		}
	})
	// Each of the following test one fixture plucked from the Spec's examples.
	b.Run("B", func(b *testing.B) {
		benchOne(b, []byte("CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L"))
	})
	b.Run("BT", func(b *testing.B) {
		benchOne(b, []byte("CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P"))
	})
	b.Run("BE", func(b *testing.B) {
		benchOne(b, []byte("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H"))
	})
	b.Run("BTES", func(b *testing.B) {
		benchOne(b, []byte("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green"))
	})
}

func benchAppendV3(b *testing.B) {
	buf := make([]byte, 0, 1024) // Is it cheating to oversize this?
	benchOne := func(b *testing.B, vec []byte) {
		b.Helper()
		b.Attr("input", string(vec))
		var v V3
		if err := v.UnmarshalText(vec); err != nil {
			b.Fatal(err)
		}
		var err error
		var x []byte
		b.ReportAllocs()

		for b.Loop() {
			x, err = v.AppendText(buf)
			if err != nil {
				b.Error(err)
			}
			_ = x
		}
	}

	b.Run("List", func(b *testing.B) {
		vecs := loadVectorList(b, `v31_score.list`)
		todo := make([][]byte, 10)
		for i := range todo {
			todo[i] = vecs[rand.N(len(vecs))]
		}
		for _, vec := range todo {
			b.Run("", func(b *testing.B) { benchOne(b, vec) })
		}
	})
	b.Run("Heartbleed", func(b *testing.B) {
		benchOne(b, []byte("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"))
	})
}

func benchAppendV2(b *testing.B) {
	buf := make([]byte, 0, 1024) // Is it cheating to oversize this?
	benchOne := func(b *testing.B, vec []byte) {
		b.Helper()
		b.Attr("input", string(vec))
		var v V2
		if err := v.UnmarshalText(vec); err != nil {
			b.Fatal(err)
		}
		var err error
		var x []byte
		b.ReportAllocs()

		for b.Loop() {
			x, err = v.AppendText(buf)
			if err != nil {
				b.Error(err)
			}
			_ = x
		}
	}

	b.Run("List", func(b *testing.B) {
		vecs := loadVectorList(b, `v2_score.list`)
		todo := make([][]byte, 10)
		for i := range todo {
			todo[i] = vecs[rand.N(len(vecs))]
		}
		for _, vec := range todo {
			b.Run("", func(b *testing.B) { benchOne(b, vec) })
		}
	})
	b.Run("Heartbleed", func(b *testing.B) {
		benchOne(b, []byte("AV:N/AC:L/Au:N/C:P/I:N/A:N"))
	})
}
