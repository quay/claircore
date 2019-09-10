package defaultscanner

import "encoding/json"

// ScannerState is a specific state in the scanner fsm
type ScannerState int

func (ss ScannerState) String() string {
	names := [...]string{
		"Terminal",
		"CheckManifest",
		"FetchAndStackLayers",
		"LayerScan",
		"BuildImageResult",
		"BuildLayerResults",
		"ScanError",
		"ScanFinished",
	}
	return names[ss]
}

func (ss *ScannerState) FromString(state string) {
	switch state {
	case "Terminal":
		*ss = Terminal
	case "CheckManifest":
		*ss = CheckManifest
	case "FetchAndStackLayers":
		*ss = FetchAndStackLayers
	case "LayerScan":
		*ss = LayerScan
	case "BuildImageResult":
		*ss = BuildImageResult
	case "BuildLayerResult":
		*ss = BuildLayerResult
	case "ScanError":
		*ss = ScanError
	case "ScanFinished":
		*ss = ScanFinished
	}
}

func (ss ScannerState) MarshalJSON() ([]byte, error) {
	return json.Marshal(ss.String())
}

func (ss *ScannerState) UnmarshalJSON(data []byte) error {
	var temp string
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	ss.FromString(temp)
	return nil
}
