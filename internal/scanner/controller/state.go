package controller

import "encoding/json"

// State is a specific state in the scanner fsm
type State int

func (ss State) String() string {
	names := [...]string{
		"Terminal",
		"CheckManifest",
		"FetchLayers",
		"ScanLayers",
		"Coalesce",
		"ScanError",
		"ScanFinished",
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
	case "ScanError":
		*ss = ScanError
	case "ScanFinished":
		*ss = ScanFinished
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
