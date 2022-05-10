package java

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

func TestMatcher(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	m := &matcher{}
	var (
		rs []claircore.IndexRecord
		v  claircore.Vulnerability
	)
	f, err := os.Open("testdata/matcher_indexrecord.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&rs); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open("testdata/matcher_vulnerability.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&v); err != nil {
		t.Fatal(err)
	}

	for i := range rs {
		r := &rs[i]
		if !m.Filter(r) {
			continue
		}
		ok, err := m.Vulnerable(ctx, r, &v)
		if err != nil {
			t.Error(err)
			continue
		}
		t.Logf("vulnerable? %v", ok)
	}
}

func TestMavenVersions(t *testing.T) {
	t.Run("Parse", func(t *testing.T) {
		tc := []string{
			"1.0",
			"1.0.1",
			"1-SNAPSHOT",
			"1-alpha10-SNAPSHOT",
		}
		for _, in := range tc {
			v, err := parseMavenVersion(in)
			t.Logf("in: %q, got: %q", in, v.C.String())
			if err != nil {
				t.Error(err)
			}
		}
	})
	t.Run("Compare", func(t *testing.T) {
		op := map[int]string{
			0:  "==",
			1:  ">",
			-1: "<",
		}
		tc := []struct {
			aIn, bIn string
			want     int
		}{
			// From the wiki
			{aIn: "1.0", bIn: "1.0-alpha", want: 1},
			{aIn: "1.0", bIn: "1", want: 0},
			{aIn: "1-beta", bIn: "1-xyz", want: -1},
			{aIn: "1-beta", bIn: "1-abc", want: -1},
			{aIn: "1.0", bIn: "1.0-abc", want: -1},
			{aIn: "1.0-alpha-10", bIn: "1.0-alpha-2", want: 1},
			{aIn: "1.0-alpha-1.0", bIn: "1.0-alpha-1", want: 0},
			{aIn: "1.0-alpha-1.2", bIn: "1.0-alpha-2", want: -1},
			// ported from the maven tests: https://github.com/apache/maven/blob/maven-3.9.x/maven-artifact/src/test/java/org/apache/maven/artifact/versioning/ComparableVersionTest.java
			{"1", "1", 0},
			{"1", "1.0", 0},
			{"1", "1.0.0", 0},
			{"1.0", "1.0.0", 0},
			{"1", "1-0", 0},
			{"1", "1.0-0", 0},
			{"1.0", "1.0-0", 0},
			// no separator between number and character
			{"1a", "1-a", 0},
			{"1a", "1.0-a", 0},
			{"1a", "1.0.0-a", 0},
			{"1.0a", "1-a", 0},
			{"1.0.0a", "1-a", 0},
			{"1x", "1-x", 0},
			{"1x", "1.0-x", 0},
			{"1x", "1.0.0-x", 0},
			{"1.0x", "1-x", 0},
			{"1.0.0x", "1-x", 0},
			// aliases
			{"1ga", "1", 0},
			{"1release", "1", 0},
			{"1final", "1", 0},
			{"1cr", "1rc", 0},
			// special "aliases" a, b and m for alpha, beta and milestone
			{"1a1", "1-alpha-1", 0},
			{"1b2", "1-beta-2", 0},
			{"1m3", "1-milestone-3", 0},
			// case insensitive
			{"1X", "1x", 0},
			{"1A", "1a", 0},
			{"1B", "1b", 0},
			{"1M", "1m", 0},
			{"1Ga", "1", 0},
			{"1GA", "1", 0},
			{"1RELEASE", "1", 0},
			{"1release", "1", 0},
			{"1RELeaSE", "1", 0},
			{"1Final", "1", 0},
			{"1FinaL", "1", 0},
			{"1FINAL", "1", 0},
			{"1Cr", "1Rc", 0},
			{"1cR", "1rC", 0},
			{"1m3", "1Milestone3", 0},
			{"1m3", "1MileStone3", 0},
			{"1m3", "1MILESTONE3", 0},
			// nonequalities:
			{"1", "2", -1},
			{"1.5", "2", -1},
			{"1", "2.5", -1},
			{"1.0", "1.1", -1},
			{"1.1", "1.2", -1},
			{"1.0.0", "1.1", -1},
			{"1.0.1", "1.1", -1},
			{"1.1", "1.2.0", -1},
			{"1.0-alpha-1", "1.0", -1},
			{"1.0-alpha-1", "1.0-alpha-2", -1},
			{"1.0-alpha-1", "1.0-beta-1", -1},
			{"1.0-beta-1", "1.0-SNAPSHOT", -1},
			{"1.0-SNAPSHOT", "1.0", -1},
			{"1.0-alpha-1-SNAPSHOT", "1.0-alpha-1", -1},
			{"1.0", "1.0-1", -1},
			{"1.0-1", "1.0-2", -1},
			{"1.0.0", "1.0-1", -1},
			{"2.0-1", "2.0.1", -1},
			{"2.0.1-klm", "2.0.1-lmn", -1},
			{"2.0.1", "2.0.1-xyz", -1},
			{"2.0.1", "2.0.1-123", -1},
			{"2.0.1-xyz", "2.0.1-123", -1},
			// MNG-5568
			{"6.1.0rc3", "6.1.0", -1},
			{"6.1.0rc3", "6.1H.5-beta", -1},
			{"6.1.0", "6.1H.5-beta", -1},
			// MNG-6572
			{"20190126.230843", "1234567890.12345", -1},
			{"1234567890.12345", "123456789012345.1H.5-beta", -1},
			{"20190126.230843", "123456789012345.1H.5-beta", -1},
			{"123456789012345.1H.5-beta", "12345678901234567890.1H.5-beta", -1},
			{"1234567890.12345", "12345678901234567890.1H.5-beta", -1},
			{"20190126.230843", "12345678901234567890.1H.5-beta", -1},
			// MNG-6964
			{"1-0.alpha", "1", -1},
			{"1-0.beta", "1", -1},
			{"1-0.alpha", "1-0.beta", -1},
		}
		for _, tc := range tc {
			a, err := parseMavenVersion(tc.aIn)
			if err != nil {
				t.Error(err)
			}
			b, err := parseMavenVersion(tc.bIn)
			if err != nil {
				t.Error(err)
			}
			got, want := a.Compare(b), tc.want
			t.Log(tc.aIn, op[got], tc.bIn)
			if got != want {
				t.Logf("a: %+v", a.C)
				t.Logf("b: %+v", b.C)
				t.Errorf("wanted: %s %s %s", tc.aIn, op[want], tc.bIn)
			}
			if want == 0 {
				continue
			}
			got, want = b.Compare(a), -1*tc.want
			t.Log(tc.bIn, op[got], tc.aIn)
			if got != want {
				t.Logf("b: %+v", b.C)
				t.Logf("a: %+v", a.C)
				t.Errorf("wanted: %s %s %s", tc.bIn, op[want], tc.aIn)
			}
		}
	})
}
