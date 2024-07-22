package cvss

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// LoadVectorList loads a list of newline-separated CVSS vectors, omitting empty
// lines and lines starting with '#'.
func loadVectorList(t testing.TB, name string) [][]byte {
	t.Helper()
	in, err := os.ReadFile(filepath.Join(`testdata`, name))
	if err != nil {
		t.Fatal(err)
	}
	vecs := bytes.Split(in, []byte{'\n'})
	return slices.DeleteFunc(vecs, func(b []byte) bool {
		return len(b) == 0 || b[0] == '#'
	})
}

func BenchmarkUnmarshal(b *testing.B) {
	b.Run("V2", benchmarkV2)
	b.Run("V3", benchmarkV3)
	b.Run("V4", benchmarkV4)
}

func benchmarkV4(b *testing.B) {
	benchOne := func(b *testing.B, vec string) {
		b.Helper()
		in := []byte(vec)
		vs := make([]V4, b.N)

		b.SetBytes(int64(len(vec)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			vs[i].UnmarshalText(in)
		}
	}

	// Tests a list of different vectors.
	b.Run("List", func(b *testing.B) {
		vecs := loadVectorList(b, `v4_bench.list`)
		var n int64
		for _, vec := range vecs {
			n += int64(len(vec))
		}
		b.SetBytes(n)
		vs := make([]V4, b.N*len(vecs))
		b.Logf("allocations reported per list, not per vector (%d elements)", len(vecs))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j, vec := range vecs {
				vs[i+j].UnmarshalText(vec)
			}
		}
		b.StopTimer()
		// Recalculate time-per-op into per-vector instead of per-list.
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(vecs)), "ns/op")
	})

	// Each of the following test one fixture plucked from the Spec's examples.

	b.Run("B", func(b *testing.B) {
		benchOne(b, "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L")
	})
	b.Run("BT", func(b *testing.B) {
		benchOne(b, "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P")
	})
	b.Run("BE", func(b *testing.B) {
		benchOne(b, "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H")
	})
	b.Run("BTES", func(b *testing.B) {
		benchOne(b, "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green")
	})
}

func benchmarkV3(b *testing.B) {
	// Tests a list of different vectors.
	b.Run("List", func(b *testing.B) {
		vecs := loadVectorList(b, `v3_bench.list`)
		var n int64
		for _, vec := range vecs {
			n += int64(len(vec))
		}
		b.SetBytes(n)
		vs := make([]V3, b.N*len(vecs))
		b.Logf("allocations reported per list, not per vector (%d elements)", len(vecs))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j, vec := range vecs {
				vs[i+j].UnmarshalText(vec)
			}
		}
		b.StopTimer()
		// Recalculate time-per-op into per-vector instead of per-list.
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(vecs)), "ns/op")
	})

	b.Run("Heartbleed", func(b *testing.B) {
		vec := []byte("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
		vs := make([]V3, b.N)

		b.SetBytes(int64(len(vec)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			vs[i].UnmarshalText(vec)
		}
	})
}

func benchmarkV2(b *testing.B) {
	// Tests a list of different vectors.
	b.Run("List", func(b *testing.B) {
		vecs := loadVectorList(b, `v2_bench.list`)
		var n int64
		for _, vec := range vecs {
			n += int64(len(vec))
		}
		b.SetBytes(n)
		vs := make([]V2, b.N*len(vecs))
		b.Logf("allocations reported per list, not per vector (%d elements)", len(vecs))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j, vec := range vecs {
				vs[i+j].UnmarshalText(vec)
			}
		}
		b.StopTimer()
		// Recalculate time-per-op into per-vector instead of per-list.
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(vecs)), "ns/op")
	})

	b.Run("Heartbleed", func(b *testing.B) {
		vec := []byte("AV:N/AC:L/Au:N/C:P/I:N/A:N")
		vs := make([]V2, b.N)

		b.SetBytes(int64(len(vec)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			vs[i].UnmarshalText(vec)
		}
	})
}
