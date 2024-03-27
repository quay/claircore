package plugin

import (
	"context"
	"sync"

	"github.com/quay/zlog"
)

// DocOnce backs the [printDoc] function.
var docOnce = struct {
	sync.RWMutex
	m map[string]struct{}
}{
	m: make(map[string]struct{}),
}

// PrintDoc logs the string "doc" once for the supplied "name".
func printDoc(ctx context.Context, name, doc string) {
	docOnce.RLock()
	_, done := docOnce.m[name]
	docOnce.RUnlock()
	if done {
		return
	}
	docOnce.Lock()
	_, done = docOnce.m[name]
	if !done {
		docOnce.m[name] = struct{}{}
	}
	docOnce.Unlock()
	if done {
		return
	}
	if doc == "" {
		return
	}
	zlog.Info(ctx).Str("name", name).
		Str("description", doc).
		Msg("configuration documentation")
}
