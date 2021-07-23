package integration

import (
	"os"
	"runtime"
)

var (
	dbOS      string
	dbArch    string
	dbVersion string
)

func init() {
	dbOS = runtime.GOOS
	dbVersion = v12
	dbArch = runtime.GOARCH

	// See if a different version was requested
	switch e := os.Getenv(EnvPGVersion); e {
	case "13":
		dbVersion = v13
	case "12":
		// default, set above
	case "11":
		dbVersion = v11
	case "10":
		dbVersion = v10
	case "9":
		dbVersion = v9
	}

	// This is a per-OS function.
	fixupName(&dbArch)
}
