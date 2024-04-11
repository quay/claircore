//go:build !linux

package integration

import (
	"runtime"
)

func findArch() (arch string) {
	arch = runtime.GOARCH
	ok := false
	switch runtime.GOOS {
	case "darwin":
		switch arch {
		case "arm64":
			arch += "v8"
			fallthrough
		case "amd64": // OK
			ok = true
		default:
		}
	case "windows":
		switch arch {
		case "amd64": // OK
			ok = true
		default:
		}
	default:
	}
	if !ok {
		// Will cause the [startEmbedded] function to print a warning and fail
		// the test if the environment requires an embedded database.
		return ""
	}
	return arch
}
