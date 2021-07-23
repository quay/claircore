package integration

import (
	"os"
	"strings"
	"syscall"
)

// the zonkyio/embedded-postgres-binaries project produces
// arm binaries with the following name schema:
// 32bit: arm32v6 / arm32v7
// 64bit (aarch64): arm64v8

func fixupName(dbArch *string) {
	switch *dbArch {
	case "arm64":
		*dbArch += "v8"
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
			*dbArch += "32v7"
		case strings.HasPrefix(mach, "armv6"):
			*dbArch += "32v6"
		}
	}
	// if on alpine
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		*dbArch += "-alpine"
	}
}
