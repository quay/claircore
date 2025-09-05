package libindex

import (
	"fmt"
	"math/rand/v2"
)

func fetchFilename() string {
	return fmt.Sprintf("fetcher.%08x", rand.Uint32())
}
