package acceptance

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/claircore/toolkit/fixtures"
)

func TestCompare(t *testing.T) {
	tests := []struct {
		name     string
		expected []fixtures.ManifestRecord
		actual   []Result
		want     *Comparison
	}{
		{
			name: "AllMatchAffected",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusAffected},
				{ID: "CVE-2024-5678", Product: "openssl@1.1.1", Status: fixtures.StatusAffected},
			},
			actual: []Result{
				{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusAffected},
				{TrackingID: "CVE-2024-5678", ProductID: "openssl@1.1.1", Status: fixtures.StatusAffected},
			},
			want: &Comparison{
				Matches: []Match{
					{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusAffected},
					{TrackingID: "CVE-2024-5678", ProductID: "openssl@1.1.1", Status: fixtures.StatusAffected},
				},
			},
		},
		{
			name: "NotAffectedStatusMatch",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusNotAffected},
			},
			actual: []Result{
				{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusNotAffected},
			},
			want: &Comparison{
				Matches: []Match{
					{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusNotAffected},
				},
			},
		},
		{
			name: "StatusMismatchExpectedNotAffectedGotAffected",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusNotAffected},
			},
			actual: []Result{
				{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusAffected},
			},
			want: &Comparison{
				Mismatches: []Mismatch{
					{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Expected: fixtures.StatusNotAffected, Actual: fixtures.StatusAffected},
				},
			},
		},
		{
			name: "AbsentNotInResultsIsSuccess",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusAbsent},
			},
			actual: []Result{},
			want: &Comparison{
				Matches: []Match{
					{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusAbsent},
				},
			},
		},
		{
			name: "AbsentFoundInResultsIsFailure",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusAbsent},
			},
			actual: []Result{
				{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusAffected},
			},
			want: &Comparison{
				Mismatches: []Mismatch{
					{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Expected: fixtures.StatusAbsent, Actual: fixtures.StatusAffected},
				},
			},
		},
		{
			name: "MissingExpectedAffected",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusAffected},
			},
			actual: []Result{},
			want: &Comparison{
				Misses: []fixtures.ManifestRecord{
					{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusAffected},
				},
			},
		},
		{
			name: "ExtraResultsOk",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1234", Product: "glibc@2.28", Status: fixtures.StatusAffected},
			},
			actual: []Result{
				{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusAffected},
				{TrackingID: "CVE-2024-9999", ProductID: "curl@7.88", Status: fixtures.StatusAffected},
			},
			want: &Comparison{
				Matches: []Match{
					{TrackingID: "CVE-2024-1234", ProductID: "glibc@2.28", Status: fixtures.StatusAffected},
				},
				Extras: []Result{
					{TrackingID: "CVE-2024-9999", ProductID: "curl@7.88", Status: fixtures.StatusAffected},
				},
			},
		},
		{
			name: "ComplexScenario",
			expected: []fixtures.ManifestRecord{
				{ID: "CVE-2024-1111", Product: "pkg-a@1.0", Status: fixtures.StatusAffected},
				{ID: "CVE-2024-2222", Product: "pkg-b@2.0", Status: fixtures.StatusNotAffected},
				{ID: "CVE-2024-3333", Product: "pkg-c@3.0", Status: fixtures.StatusAffected},
				{ID: "CVE-2024-6666", Product: "pkg-f@6.0", Status: fixtures.StatusAbsent},
			},
			actual: []Result{
				{TrackingID: "CVE-2024-1111", ProductID: "pkg-a@1.0", Status: fixtures.StatusAffected},
				{TrackingID: "CVE-2024-2222", ProductID: "pkg-b@2.0", Status: fixtures.StatusAffected},
				{TrackingID: "CVE-2024-5555", ProductID: "pkg-e@5.0", Status: fixtures.StatusAffected},
				// pkg-c@3.0 missing (fail)
				// pkg-f@6.0 absent and not in results (success)
			},
			want: &Comparison{
				Matches: []Match{
					{TrackingID: "CVE-2024-1111", ProductID: "pkg-a@1.0", Status: fixtures.StatusAffected},
					{TrackingID: "CVE-2024-6666", ProductID: "pkg-f@6.0", Status: fixtures.StatusAbsent},
				},
				Mismatches: []Mismatch{
					{TrackingID: "CVE-2024-2222", ProductID: "pkg-b@2.0", Expected: fixtures.StatusNotAffected, Actual: fixtures.StatusAffected},
				},
				Misses: []fixtures.ManifestRecord{
					{ID: "CVE-2024-3333", Product: "pkg-c@3.0", Status: fixtures.StatusAffected},
				},
				Extras: []Result{
					{TrackingID: "CVE-2024-5555", ProductID: "pkg-e@5.0", Status: fixtures.StatusAffected},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Compare(tc.expected, tc.actual)

			if got.Passed() != tc.want.Passed() {
				t.Errorf("Passed: got %v, want %v", got.Passed(), tc.want.Passed())
			}
			if diff := cmp.Diff(got.Matches, tc.want.Matches); diff != "" {
				t.Errorf("Matches mismatch (-got +want):\n%s", diff)
			}
			if diff := cmp.Diff(got.Mismatches, tc.want.Mismatches); diff != "" {
				t.Errorf("Mismatches mismatch (-got +want):\n%s", diff)
			}
			if diff := cmp.Diff(got.Misses, tc.want.Misses); diff != "" {
				t.Errorf("Misses mismatch (-got +want):\n%s", diff)
			}
			if diff := cmp.Diff(got.Extras, tc.want.Extras); diff != "" {
				t.Errorf("Extras mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

