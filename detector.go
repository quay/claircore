package claircore

type Detector struct {
	// Name of the detector.
	Name string `json:"name"`
	// Version of the detector.
	Version string `json:"version"`
	// Kind of the detector.
	Kind string `json:"kind"`
}
