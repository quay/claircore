package claircore

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDetectorMarshalText(t *testing.T) {
	tests := []struct {
		name     string
		detector Detector
		want     string
	}{
		{
			name:     "valid",
			detector: Detector{Name: "test", Version: "1.0.0", Kind: "package"},
			want:     "urn:claircore:detector:test:1.0.0:package"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.detector.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText: %v", err)
			}
			if !cmp.Equal(tc.want, string(got)) {
				t.Errorf("MarshalText: want %s, got %s", tc.want, string(got))
			}
		})
	}
}

func TestDetectorUnmarshalText(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want Detector
	}{
		{
			name: "valid",
			uri:  "urn:claircore:detector:test:1.0.0:package",
			want: Detector{Name: "test", Version: "1.0.0", Kind: "package"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got Detector
			if err := got.UnmarshalText([]byte(tc.uri)); err != nil {
				t.Fatalf("UnmarshalText: %v", err)
			}
			if !cmp.Equal(tc.want, got) {
				t.Errorf("UnmarshalText: want %v, got %v", tc.want, got)
			}
		})
	}
}
