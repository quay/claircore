package libindex

import (
	"fmt"
	"math/rand/v2"
)

func fetchFilename() string {
	return fmt.Sprintf("fetcher.%08x", rand.Uint32())
}

// TryTMPFILE is a testing hook that allows disabling use of O_TMPFILE.
//
// This should be optimized out in non-test builds.
// This flag does nothing on a non-Linux OS.
var tryTMPFILE = true
