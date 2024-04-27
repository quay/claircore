package indexer

import "context"

// DynamicPlugin is an interface for registering additional plugins at runtime.
//
// The indexer attempts to call the [Run] method only once, but the
// implementation should be idempotent.
type DynamicPlugin interface {
	Run(context.Context) error
}
