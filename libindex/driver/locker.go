package driver

import "context"

type Locker interface {
	TryLock(context.Context, string) (context.Context, context.CancelFunc)
	Lock(context.Context, string) (context.Context, context.CancelFunc)
	Close(context.Context) error
}
