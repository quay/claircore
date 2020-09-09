# LibIndex Usage
LibIndex is the Go package responsible for fetching container image layers, identifying packages, distributions, and repositories within these layers, and computing a final coalesced Index Report.

An Index Report is primarily used as input to LibVuln's vulnerability matching process.

## Usage
LibIndex is runtime constructed via the libindex.New method. New requires an libindex.Opts struct.

### Opts
```go
// Opts are depedencies and options for constructing an instance of libindex
type Opts struct {
	// the connection string for the datastore specified above
	ConnString string
	// how often we should try to acquire a lock for scanning a given manifest if lock is taken
	ScanLockRetry time.Duration
	// the number of layers to be scanned in parallel.
	LayerScanConcurrency int
	// NoLayerValidation controls whether layers are checked to actually be
	// content-addressed. With this option toggled off, callers can trigger
	// layers to be indexed repeatedly by changing the identifier in the
	// manifest.
	NoLayerValidation bool
	// set to true to have libindex check and potentially run migrations
	Migrations bool
	// provides an alternative method for creating a scanner during libindex runtime
	// if nil the default factory will be used. useful for testing purposes
	ControllerFactory ControllerFactory
	// a list of ecosystems to use which define which package databases and coalescing methods we use
	Ecosystems []*indexer.Ecosystem
	// Airgap should be set to disallow any scanners that mark themselves as
	// making network calls.
	Airgap bool
	// ScannerConfig holds functions that can be passed into configurable
	// scanners. They're broken out by kind, and only used if a scanner
	// implements the appropriate interface.
	//
	// Providing a function for a scanner that's not expecting it is not a fatal
	// error.
	ScannerConfig struct {
		Package, Dist, Repo map[string]func(interface{}) error
	}
}
```

The above outlines the relevant bits of the Opts structure.

Providing a nil "Ecosystems" slice will supply the default set, instructing LibIndex to index for all supported content in a layer, and is typically desired.

### Construction
Constructing LibIndex is straight forward.

```go
opts := libindex.Opts{
}

ctx := context.TODO()
lib, err := libindex.New(ctx, opts)
if err != nil {
    log.Fatal(err)
}
defer lib.Close() // remember to cleanup when done.
```

The constructing code should provide a valid ctx tied to some lifetime.

### Indexing
Indexing is the process of submitting a manifest to LibIndex, fetching the manifest's layers, indexing their contents, and coalescing a final Index Report.

Coalescing is the act of computing a final set of contents (packages, distributions, repos) from a set of layers. Since layers maybe shared between many manifests, the final contents of a manifest must be computed.

To perform an Index you must provide a claircore.Manifest data struture to the Index method.
The Manifest data structure describes an image manifest's layers and where they can be fetched from.

```go
m := claircore.Manifest{
  ...
}

ctx := context.TODO()
ir, err := lib.Index(ctx, m)
```

The Index method will block until an claircore.IndexReport is returned.
The context should be bound to some valid lifetime such as a request. 

As the Indexer works on the manifest it will update its database throughout the process.
You may view the status of an index report via the "IndexReport" method. 

```go
ctx := context.TODO()
ir, err := lib.IndexReport(ctx, m.Digest)
```

LibIndex performs its work incrementally and saves state as it goes along. If LibIndex encounters an intermittent error during the index (for example, due to network failure while fetching a layer), when the manifest is resubmitted only the layers not yet indexed will be fetched and processed. 

### State
LibIndex treats layers as content addressable. Once a layer identified by a particular hash is indexed its contents are definitively known. A request to re-index a known layer results in returning the previous successful response.

This comes in handy when dealing with base layers. The Ubuntu base layer is seen very often across container registries. Treating this layer as content addressable precludes the need to fetch and index the layer every time LibIndex encounters it in a manifest.

There are times where re-indexing the same layer is necessary however. At the point where LibIndex realizes a new version of a component has not indexed a layer being submitted it will perform the indexing operation.

A client must notice that LibIndex has updated one of its components and subsequently resubmit Manifests. The State endpoint is implemented for this reason.

Clients may query the State endpoint to receive an opaque string acting as a cookie, identifying a unique state of LibIndex. When a client sees this cookie change it should re-submit manifests to LibIndex to obtain a new index report.

```go
ctx := context.TODO()
state, err := lib.State(ctx, m.Digest)

if state != prevState {
    // re-index manifest
    ir, err := lib.Index(m)
}
```

### AffectedManifests
LibIndex is capable of providing a client with all manifests affected by a set of vulnerabilities.
This functionality is designed for use with a notification mechanism.

```go
ctx := context.TODO()
affected, err := lib.AffectedManifests(ctx, vulns)

for manifest, vulns := range affected.VulnerableManifests {
    for _, vuln := range vulns {
        fmt.Printf("vuln affecting manifest %s: %+v", manifest, vuln)
    }
}
```

The slice of vulnerabilities returned for each manifest hash will be sorted by claircore.NormalizedSeverity in "most severe" descending order.
