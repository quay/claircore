package integration

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// the zonkyio/embedded-postgres-binaries project produces
// arm binaries with the following name schema:
// 32bit: arm32v6 / arm32v7
// 64bit (aarch64): arm64v8

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
			panic(err)
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
		}
	case "ppc64le": // OK
	case "amd64": // OK
	default:
		panic(fmt.Sprintf(
			`unsupported platform "%s/%s"; see https://mvnrepository.com/artifact/io.zonky.test.postgres/embedded-postgres-binaries-bom`,
			runtime.GOOS, runtime.GOARCH,
		))
	}
	// If on alpine:
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		arch += "-alpine"
	}

	return arch
}
