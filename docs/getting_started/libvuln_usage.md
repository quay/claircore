# Libvuln Usage
Libvuln is the Go package responsible for keeping the database of
vulnerabilities consistent, matching container image contents with
vulnerabilities, and reporting diffs between updates of the same security
database. 

## Usage 
`Libvuln` is runtime constructed via the `libvuln.New` method. `New` requires a
`libvuln.Opts` struct.

### Opts
{{# godoc libvuln.Opts }}

The above outlines the relevant bits of the Opts structure.

### Construction
Constructing Libvuln is straight forward.

```go
{{#include ../libvuln_test.go:new}}
```

The constructing code should provide a valid Context tied to some lifetime.

On construction, `New` will block until the security databases are initialized.
Expect some delay before this method returns.

### Scanning
Scanning is the process of taking a `claircore.IndexReport` comprised of a
Manifest's content and determining which vulnerabilities affect the Manifest. A
`claircore.VulnerabilityReport` will be returned with these details.

```go
{{#include ../libvuln_test.go:scan}}
```

In the above example, `Libindex` is used to generate a `claircore.IndexReport`.
The index report is then provided to `Libvuln` and a subsequent vulnerability
report identifying any vulnerabilities affecting the manifest is returned.

### Updates API
By default, Libvuln manages a set of long running updaters responsible for
periodically fetching and loading new advisory contents into its database. The
Updates API allows a client to view and manipulate aspects of the update
operations that updaters perform.

In this getting started guide, we will only cover the two methods most
interesting to new users.

#### UpdateOperations
This API provides a list of recent update operations performed by implemented updaters. 
The `UpdateOperation` slice returned will be sorted by latest timestamp descending. 
```go
{{#include ../libvuln_test.go:ops}}
{{#include ../libvuln_test.go:ops_print}}
```

#### UpdateDiff
Mostly used by ClairV4's notification subsystem, this endpoint will provide the
caller with any removed or added vulnerabilities between two update operations.
Typically a diff takes places against two versions of the same data source. This
is useful to inform downstream applications what new vulnerabilities have
entered the system.

```go
{{#include ../libvuln_test.go:ops}}
{{#include ../libvuln_test.go:ops_diff}}
```
