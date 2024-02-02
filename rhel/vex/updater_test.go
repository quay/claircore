package vex

import (
	"errors"
	"testing"

	"github.com/quay/claircore/libvuln/driver"
)

func TestFingerprintRoundTrip(t *testing.T) {
	testcases := []struct {
		name string
		val  driver.Fingerprint
		err  bool
	}{
		{
			name: "simple",
			val:  `one\two\2006-01-02T15:04:05Z\1`,
			err:  false,
		},
		{
			name: "date error",
			val:  `one\two\2006-01-02T15:04:05ZMore\1`,
			err:  true,
		},
		{
			name: "etag error",
			val:  `one\tw\o\2006-01-02T15:04:05Z\123`,
			err:  true,
		},
		{
			name: "missing version error",
			val:  `one\tw\o\2006-01-02T15:04:05Z`,
			err:  true,
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := parseFingerprint(tt.val)
			if err != nil {
				t.Log("error", err)
			}
			if !tt.err {
				if !errors.Is(err, nil) {
					t.Fatal("unexpected error:", err)
				}
				if fp.String() != string(tt.val) {
					t.Errorf("expected fingerprint: %s but got: %s", tt.val, fp)
				}

			}
			if tt.err && errors.Is(err, nil) {
				t.Fatal("unexpected non-error")
			}
		})
	}
}
