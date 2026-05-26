package rhcc

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
)

func TestMatcherVulnerable(t *testing.T) {
	t.Parallel()
	ctx := test.Logging(t)
	m := &matcher{}

	t.Run("Inverted", func(t *testing.T) {
		record := &claircore.IndexRecord{
			Package:    &claircore.Package{Name: "mta/mta-rhel8-operator", Version: "7.0.3-13"},
			Repository: &GoldRepo,
		}
		vuln := &claircore.Vulnerability{
			Name:   "CVE-2024-24786",
			Invert: true,
			Repo:   &GoldRepo,
		}
		got, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Error("expected vulnerable=true for inverted vulnerability")
		}
	})

	t.Run("Normal", func(t *testing.T) {
		record := &claircore.IndexRecord{
			Package:    &claircore.Package{Name: "quay/quay-rhel8", Version: "v3.5.5-4"},
			Repository: &GoldRepo,
		}
		vuln := &claircore.Vulnerability{
			Name:           "CVE-2023-12345",
			FixedInVersion: "v3.5.6-1",
			Repo:           &GoldRepo,
		}
		got, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Error("expected vulnerable=true when version < fixed")
		}
	})

	t.Run("Fixed", func(t *testing.T) {
		record := &claircore.IndexRecord{
			Package:    &claircore.Package{Name: "quay/quay-rhel8", Version: "v3.5.7-1"},
			Repository: &GoldRepo,
		}
		vuln := &claircore.Vulnerability{
			Name:           "CVE-2023-12345",
			FixedInVersion: "v3.5.6-1",
			Repo:           &GoldRepo,
		}
		got, err := m.Vulnerable(ctx, record, vuln)
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Error("expected vulnerable=false when version >= fixed")
		}
	})
}
