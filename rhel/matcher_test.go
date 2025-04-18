package rhel

import (
	"testing"

	"github.com/quay/claircore/toolkit/types/cpe"
)

func TestIsCPEStringSubsetMatch(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name               string
		recordCPE, vulnCPE cpe.WFN
		match              bool
	}{
		{
			name:      "simple_case",
			recordCPE: cpe.MustUnbind("cpe:/a:redhat:openshift:4.13::el8"),
			vulnCPE:   cpe.MustUnbind("cpe:/a:redhat:openshift:4"),
			match:     true,
		},
		{
			name:      "wrong_minor",
			recordCPE: cpe.MustUnbind("cpe:/a:redhat:openshift:4.13::el8"),
			vulnCPE:   cpe.MustUnbind("cpe:/a:redhat:openshift:4.1::el8"),
			match:     false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tt := tc
			matched := isCPESubstringMatch(tt.recordCPE, tt.vulnCPE)
			if matched != tt.match {
				t.Errorf("unexpected matching %s and %s", tt.recordCPE, tt.vulnCPE)
			}
		})
	}
}
