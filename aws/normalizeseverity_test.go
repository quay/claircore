package aws

import (
	"testing"

	"github.com/quay/claircore"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := map[string]struct {
		severity string
		want     claircore.Severity
	}{
		"lowercase low":       {severity: "low", want: claircore.Low},
		"Amazon Low":          {severity: "Low", want: claircore.Low},
		"lowercase medium":    {severity: "medium", want: claircore.Medium},
		"Amazon Medium":       {severity: "Medium", want: claircore.Medium},
		"lowercase important": {severity: "important", want: claircore.High},
		"Amazon Important":    {severity: "Important", want: claircore.High},
		"lowercase critical":  {severity: "critical", want: claircore.Critical},
		"Amazon Critical":     {severity: "Critical", want: claircore.Critical},
		"unknown":             {severity: "unknown", want: claircore.Unknown},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := NormalizeSeverity(test.severity); got != test.want {
				t.Errorf("NormalizeSeverity(%q) = %q, want %q", test.severity, got, test.want)
			}
		})
	}
}
