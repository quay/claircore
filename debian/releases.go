package debian

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/quay/claircore"
)

var releases sync.Map

func mkDist(name string, ver int) *claircore.Distribution {
	v, _ := releases.LoadOrStore(name, &claircore.Distribution{
		PrettyName:      fmt.Sprintf("Debian GNU/Linux %d (%s)", ver, name),
		Name:            "Debian GNU/Linux",
		VersionID:       strconv.Itoa(ver),
		Version:         fmt.Sprintf("%d (%s)", ver, name),
		VersionCodeName: name,
		DID:             "debian",
	})
	return v.(*claircore.Distribution)
}

func getDist(name string) (*claircore.Distribution, error) {
	v, ok := releases.Load(name)
	if !ok {
		return nil, fmt.Errorf("debian: unknown distribution %q", name)
	}
	return v.(*claircore.Distribution), nil
}
