# Versioned Scanner
A versioned scanner is typically embedded into other scanner types.
It drives ClairCore's ability to register and understand when updaters have been changed.
Functions that want to work with a generic scanner type should use a VersionedScanner .

Implementers of this interface *must* provide a unique name.
Making changes to a scanner's implementation *must* return a new Version.
Implementers *must* return the correct kind, one of "package", "distribution", "repository"

```go
package indexer

// VersionedScanner can be embedded into specific scanner types. This allows for
// methods and functions which only need to compare names and versions of
// scanners not to require each scanner type as an argument.
type VersionedScanner interface {
	// unique name of the distribution scanner.
	Name() string
	// version of this scanner. this information will be persisted with the scan.
	Version() string
	// the kind of scanner. currently only package is implemented
	Kind() string
}
```
