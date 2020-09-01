# Repository Scanner
A RepositoryScanner should identify any repositories discovered in the provided layer.
It is OK for the scanner to identify no repositories. 

```go
package indexer

type RepositoryScanner interface {
	VersionedScanner
	Scan(context.Context, *claircore.Layer) ([]*claircore.Repository, error)
}
```
