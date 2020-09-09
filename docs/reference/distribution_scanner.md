# Distribution Scanner
A Distribution Scanner should identify any operating system distribution associated with the provided layer.
It is OK for no distribution information to be discovered.

```go
package indexer

type DistributionScanner interface {
	VersionedScanner
	Scan(context.Context, *claircore.Layer) ([]*claircore.Distribution, error)
}
```
