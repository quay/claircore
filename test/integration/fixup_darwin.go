package integration

func fixupName(dbArch *string) {
	// No arm build yet, so use the emulator.
	if *dbArch == "arm64" {
		*dbArch = "amd64"
	}
}
