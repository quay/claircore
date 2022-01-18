# Ecosystem
An Ecosystem groups together scanners and coalescers which are often used
together.  Ecosystems are usually defined in a go package that corresponds to a
package manager, such as `dpkg`.  See `dpkg/ecosystem.go` for an example.

The Indexer will retrieve artifacts from the provided scanners and provide these
scan artifacts to the coalescer in the Ecosystem.

{{# godoc internal/indexer.Ecosystem}}
