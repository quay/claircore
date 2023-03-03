package integration

import (
	"os"
	"runtime"
	"strings"
)

var (
	dbOS      string
	dbArch    string
	dbVersion string
)

func init() {
	dbOS = runtime.GOOS
	dbVersion = v15
	dbArch = runtime.GOARCH

	// See if a different version was requested
	if e := os.Getenv(EnvPGVersion); e != "" {
		if strings.Count(e, ".") == 2 {
			// Try it as a version string 🤷
			dbVersion = e
		}
		switch e {
		case "15":
			dbVersion = v15
		case "14":
			dbVersion = v14
		case "13":
			dbVersion = v13
		case "12":
			dbVersion = v12
		case "11":
			dbVersion = v11
		default: // Ignore, use what it's been set to.
		}
	}

	// This is a per-OS function.
	fixupName(&dbArch)
}
