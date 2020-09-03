# UpdaterSetFactory
An UpdaterSetFactory is a factory for runtime construction and configuration for Updaters.

```go
package driver

// UpdaterSetFactory is used to construct updaters at run-time.
type UpdaterSetFactory interface {
	UpdaterSet(context.Context) (UpdaterSet, error)
}

type UpdaterSetFactoryFunc func(context.Context) (UpdaterSet, error)

func (u UpdaterSetFactoryFunc) UpdaterSet(ctx context.Context) (UpdaterSet, error) {
	return u(ctx)
}

// StaticSet creates an UpdaterSetFunc returning the provided set.
func StaticSet(s UpdaterSet) UpdaterSetFactory {
	return UpdaterSetFactoryFunc(func(_ context.Context) (UpdaterSet, error) {
		return s, nil
	})
}

```
