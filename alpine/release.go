package alpine

// Release is a particular release of the Alpine linux distribution
type Release string

const (
	V3_10 Release = "v3.10"
	V3_9  Release = "v3.9"
	V3_8  Release = "v3.8"
	V3_7  Release = "v3.7"
	V3_6  Release = "v3.6"
	V3_5  Release = "v3.5"
	V3_4  Release = "v3.4"
	V3_3  Release = "v3.3"
)

// ReleaseToPrettyName maps a Release to the PrettyName found in alpine's os-release file.
//
// Official Alpine images consistantly have a Pretty_Name field in their os-release files.
var ReleaseToPrettyName = map[Release]string{
	V3_10: "Alpine Linux v3.10",
	V3_9:  "Alpine Linux v3.9",
	V3_8:  "Alpine Linux v3.8",
	V3_7:  "Alpine Linux v3.7",
	V3_6:  "Alpine Linux v3.6",
	V3_5:  "Alpine Linux v3.5",
	V3_4:  "Alpine Linux v3.4",
	V3_3:  "Alpine Linux v3.3",
}

// Common os-release fields applicable for *claircore.Distribution usage.
const (
	Name = "Alpine Linux"
	ID   = "alpine"
)
