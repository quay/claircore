package controller

import (
	"context"
	"encoding/json"
)

// State is a specific state in the indexer fsm
type State int

// States and their explanations.
// Each state is implemented by a stateFunc implemented in their own files.
const (
	// Terminal is the state which halts the fsm and returns the current s.result to the caller
	Terminal State = iota
	// CheckManifest determines if the manifest should be scanned.
	// if no Terminal is returned and we return the existing IndexReport.
	// Transitions: FetchLayers, Terminal
	CheckManifest
	// FetchLayers retrieves all the layers in a manifest and stacks them the same obtain the file image contents.
	// creates the "image" layer
	// Transitions: LayerScan
	FetchLayers
	// ScanLayers scans each image including the image layer and indexes the contents
	// Transitions: BuildLayerResult
	ScanLayers
	// Coalesce runs each provided ecosystem's coalescer and merges their scan results
	// Transitions: IndexManifest
	Coalesce
	// IndexManifest evaluates a coalesced IndexReport and writes it's contents
	// to the the persistence layer where it maybe searched.
	// Transitions: IndexFinished
	IndexManifest
	// IndexError state indicates a impassable error has occurred.
	// returns a ScanResult with the error field
	// Transitions: Terminal
	IndexError
	// IndexFinished state is the terminal state and should return a IndexReport
	// to the caller of Scan()
	// Transitions: Terminal
	IndexFinished
)

func (ss State) String() string {
	names := [...]string{
		"Terminal",
		"CheckManifest",
		"FetchLayers",
		"ScanLayers",
		"Coalesce",
		"IndexManifest",
		"IndexError",
		"IndexFinished",
	}
	return names[ss]
}

func (ss *State) FromString(state string) {
	switch state {
	case "Terminal":
		*ss = Terminal
	case "CheckManifest":
		*ss = CheckManifest
	case "FetchLayers":
		*ss = FetchLayers
	case "ScanLayers":
		*ss = ScanLayers
	case "Coalesce":
		*ss = Coalesce
	case "IndexManifest":
		*ss = IndexManifest
	case "IndexError":
		*ss = IndexError
	case "IndexFinished":
		*ss = IndexFinished
	}
}

func (ss State) MarshalJSON() ([]byte, error) {
	return json.Marshal(ss.String())
}

func (ss *State) UnmarshalJSON(data []byte) error {
	var temp string
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ss.FromString(temp)
	return nil
}

// stateFunc implement the logic of our controller and map directly to States.
// returning an error will exit the controller in an error state.
// returning Terminal ends the controller in a non error state.
type stateFunc func(context.Context, *Controller) (State, error)

// provides a mapping of States to their implemented stateFunc methods
var stateToStateFunc = map[State]stateFunc{
	CheckManifest: checkManifest,
	FetchLayers:   fetchLayers,
	ScanLayers:    scanLayers,
	Coalesce:      coalesce,
	IndexManifest: indexManifest,
	IndexFinished: indexFinished,
}
