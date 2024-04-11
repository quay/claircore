package integration

import (
	"os"
	"runtime"
	"strings"
	"syscall"
)

// The zonkyio/embedded-postgres-binaries project produces ARM binaries with the
// following name schema:
//
// - 32bit : arm32v6 / arm32v7
// - 64bit (aarch64): arm64v8

func findArch() (arch string) {
	arch = runtime.GOARCH
	switch arch {
	case "386":
		arch = "i" + arch
	case "arm64":
		arch += "v8"
	case "arm":
		var u syscall.Utsname
		if err := syscall.Uname(&u); err != nil {
			// Not sure why this would happen? Try to use the lowest revision
			// and let it crash otherwise.
			arch += "32v6"
			break
		}
		t := make([]byte, 0, len(u.Machine[:]))
		for _, b := range u.Machine[:] {
			if b == 0 {
				break
			}
			t = append(t, byte(b))
		}
		mach := strings.TrimRight(string(t), "\x00")
		switch {
		case strings.HasPrefix(mach, "armv7"):
			arch += "32v7"
		case strings.HasPrefix(mach, "armv6"):
			arch += "32v6"
		default:
			return ""
		}
	case "ppc64le": // OK
	case "amd64": // OK
	default:
		// Will cause the [startEmbedded] function to print a warning and fail
		// the test if the environment requires an embedded database.
		return ""
	}
	// If on alpine:
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		arch += "-alpine"
	}

	return arch
}
