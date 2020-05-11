package claircore

import "github.com/quay/claircore/pkg/cpe"

// Distribution is the accompanying system context of a package. this
// information aides in CVE detection.
//
// Distribution is modeled after the os-release file found in all linux distributions.
type Distribution struct {
	// unique ID of this distribution. this will be created as discovered by the library
	// and used for persistence and hash map indexes.
	ID string `json:"id"`
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system, excluding any version information
	// and suitable for processing by scripts or usage in generated filenames. Example: "DID=fedora" or "DID=debian".
	DID string `json:"did"`
	// A string identifying the operating system.
	// example: "Ubuntu"
	Name string `json:"name"`
	// A string identifying the operating system version, excluding any OS name information,
	// possibly including a release code name, and suitable for presentation to the user.
	// example: "16.04.6 LTS (Xenial Xerus)"
	Version string `json:"version"`
	// A lower-case string (no spaces or other characters outside of 0–9, a–z, ".", "_" and "-") identifying the operating system release code name,
	// excluding any OS name information or release version, and suitable for processing by scripts or usage in generated filenames
	// example: "xenial"
	VersionCodeName string `json:"version_code_name"`
	// A lower-case string (mostly numeric, no spaces or other characters outside of 0–9, a–z, ".", "_" and "-")
	// identifying the operating system version, excluding any OS name information or release code name,
	// example: "16.04"
	VersionID string `json:"version_id"`
	// A string identifying the OS architecture
	// example: "x86_64"
	Arch string `json:"arch"`
	// Optional common platform enumeration identifier
	CPE cpe.WFN `json:"cpe"`
	// A pretty operating system name in a format suitable for presentation to the user.
	// May or may not contain a release code name or OS version of some kind, as suitable. If not set, defaults to "PRETTY_NAME="Linux"".
	// example: "PRETTY_NAME="Fedora 17 (Beefy Miracle)"".
	PrettyName string `json:"pretty_name"`
}
