package alpine

import (
	"fmt"
	"sync"

	"github.com/quay/claircore"
)

// Alpine linux has patch releases but their security database
// aggregates security information by major release. We choose
// to normalize detected distributions into major.minor releases and
// parse vulnerabilities into major.minor releases

// release is a particular release of the Alpine linux distribution
type release [2]int

// Common os-release fields applicable for *claircore.Distribution usage.
const (
	distName = "Alpine Linux"
	distID   = "alpine"
)

var relMap sync.Map

func (r release) Distribution() *claircore.Distribution {
	// Dirty hack to keyify the release structure.
	k := int64(r[0]<<32) | int64(r[1])
	v, ok := relMap.Load(k)
	if !ok {
		v, _ = relMap.LoadOrStore(k, &claircore.Distribution{
			Name:       distName,
			DID:        distID,
			VersionID:  fmt.Sprintf("%d.%d", r[0], r[1]),
			PrettyName: fmt.Sprintf("Alpine Linux v%d.%d", r[0], r[1]),
		})
	}
	return v.(*claircore.Distribution)
}

func (r release) String() string { return fmt.Sprintf("v%d.%d", r[0], r[1]) }
