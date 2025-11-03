package claircore

import (
	"fmt"
	"strings"
)

// detectorURIPrefix is the prefix for detector URIs.
const detectorURIPrefix = "urn:claircore:detector:"

type Detector struct {
	// Name of the detector.
	Name string `json:"name"`
	// Version of the detector.
	Version string `json:"version"`
	// Kind of the detector.
	Kind string `json:"kind"`
}

// MarshalText implements [encoding.TextMarshaler].
func (d *Detector) MarshalText() ([]byte, error) {
	// Use a URI format for portability and clarity.
	// Format: urn:claircore:detector:<name>:<version>:<kind>
	return []byte(fmt.Sprintf("%s%s:%s:%s", detectorURIPrefix, d.Name, d.Version, d.Kind)), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (d *Detector) UnmarshalText(text []byte) error {
	s := string(text)
	if !strings.HasPrefix(s, detectorURIPrefix) {
		return fmt.Errorf("invalid detector uri: missing %s prefix", detectorURIPrefix)
	}
	body := strings.TrimPrefix(s, detectorURIPrefix)
	parts := strings.Split(body, ":")
	if len(parts) != 3 {
		return fmt.Errorf("invalid detector uri: want 3 parts name:version:kind")
	}
	d.Name = parts[0]
	d.Version = parts[1]
	d.Kind = parts[2]
	return nil
}
