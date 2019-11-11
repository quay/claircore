package alpine

import (
	"sync"
)

const (
	maxTokenSize = 128 * 1024
)

// bufPool provides a pool to create fixed size buffers
// for package scanning
var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, maxTokenSize)
	},
}
