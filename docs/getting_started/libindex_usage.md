# Libindex Usage
Libindex is the Go package responsible for fetching container image layers,
identifying packages, distributions, and repositories within these layers, and
computing a final coalesced Index Report.

An Index Report is primarily used as input to LibVuln's vulnerability matching
process.

## Usage
Libindex is runtime constructed via the `libindex.New` method. New requires an `libindex.Opts` struct.

### Opts
{{# godoc libindex Opts }}

The above outlines the relevant bits of the Opts structure.

Providing a nil "Ecosystems" slice will supply the default set, instructing
Libindex to index for all supported content in a layer, and is typically
desired.

### Construction
Constructing Libindex is straight forward.

```go
{{#include ../libindex_test.go:new}}
```

The constructing code should provide a valid Context tied to some lifetime.

### Indexing
Indexing is the process of submitting a manifest to Libindex, fetching the
manifest's layers, indexing their contents, and coalescing a final Index
Report.

Coalescing is the act of computing a final set of contents (packages,
distributions, repos) from a set of layers. Since layers maybe shared between
many manifests, the final contents of a manifest must be computed.

To perform an Index you must provide a claircore.Manifest data struture to the
Index method.  The Manifest data structure describes an image manifest's layers
and where they can be fetched from.

```go
{{#include ../libindex_test.go:index}}
```

The Index method will block until an claircore.IndexReport is returned.  The
context should be bound to some valid lifetime such as a request. 

As the Indexer works on the manifest it will update its database throughout the
process.  You may view the status of an index report via the "IndexReport"
method. 

```go
{{#include ../libindex_test.go:indexreport}}
```

Libindex performs its work incrementally and saves state as it goes along. If
Libindex encounters an intermittent error during the index (for example, due to
network failure while fetching a layer), when the manifest is resubmitted only
the layers not yet indexed will be fetched and processed. 

### State
Libindex treats layers as content addressable. Once a layer identified by a
particular hash is indexed its contents are definitively known. A request to
re-index a known layer results in returning the previous successful response.

This comes in handy when dealing with base layers. The Ubuntu base layer is
seen very often across container registries. Treating this layer as content
addressable precludes the need to fetch and index the layer every time Libindex
encounters it in a manifest.

There are times where re-indexing the same layer is necessary however. At the
point where Libindex realizes a new version of a component has not indexed a
layer being submitted it will perform the indexing operation.

A client must notice that Libindex has updated one of its components and
subsequently resubmit Manifests. The State endpoint is implemented for this
reason.

Clients may query the State endpoint to receive an opaque string acting as a
cookie, identifying a unique state of Libindex. When a client sees this cookie
change it should re-submit manifests to Libindex to obtain a new index report.

```go
{{#include ../libindex_test.go:state}}
```

### AffectedManifests
Libindex is capable of providing a client with all manifests affected by a set
of vulnerabilities.  This functionality is designed for use with a notification
mechanism.

```go
{{#include ../libindex_test.go:affectedmanifests}}
```

The slice of vulnerabilities returned for each manifest hash will be sorted by
`claircore.NormalizedSeverity` in "most severe" descending order.
