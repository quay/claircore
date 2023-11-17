//go:build !linux

package integration

import (
	"fmt"
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
		panic(fmt.Sprintf(
			`unsupported platform "%s/%s"; see https://mvnrepository.com/artifact/io.zonky.test.postgres/embedded-postgres-binaries-bom`,
			runtime.GOOS, runtime.GOARCH,
		))
	}
	return arch
}
