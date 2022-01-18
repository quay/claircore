# Versioned Scanner
A versioned scanner is typically embedded into other scanner types.
It drives claircore's ability to register and understand when updaters have been changed.
Functions that want to work with a generic scanner type should use a `VersionedScanner`.

Implementers of this interface *must* provide a unique name.
Making changes to a scanner's implementation *must* return a new value from `Version`.
Implementers *must* return the correct kind: one of "package", "distribution", or "repository"

{{# godoc internal/indexer.VersionedScanner}}
