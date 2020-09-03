# LibVuln Usage
LibVuln is the Go package responsible for keeping the database of vulnerabilities consistent, matching container image contents with vulnerabilities, and reporting diffs between updates of the same security database. 

## Usage 
LibVuln is runtime constructed via the libvuln.New method. New requires a libvuln.Opts struct.

### Opts
```go
type Opts struct {
	// The maximum number of database connections in the
	// connection pool.
	MaxConnPool int32
	// A connection string to the database Lbvuln will use.
	ConnString string
	// An interval on which Libvuln will check for new security database
	// updates.
	//
	// This duration will have jitter added to it, to help with smearing load on
	// installations.
	UpdateInterval time.Duration
	// Determines if Livuln will manage database migrations
	Migrations bool
	// A slice of strings representing which updaters libvuln will create.
	//
	// If nil all default UpdaterSets will be used.
	//
	// The following sets are supported:
	// "alpine"
	// "aws"
	// "debian"
	// "oracle"
	// "photon"
	// "pyupio"
	// "rhel"
	// "suse"
	// "ubuntu"
	UpdaterSets []string
	// A list of out-of-tree updaters to run.
	//
	// This list will be merged with any defined UpdaterSets.
	//
	// If you desire no updaters to run do not add an updater
	// into this slice.
	Updaters []driver.Updater
	// A list of out-of-tree matchers you'd like libvuln to
	// use.
	//
	// This list will me merged with the default matchers.
	Matchers []driver.Matcher

	// UpdateWorkers controls the number of update workers running concurrently.
	// If less than or equal to zero, a sensible default will be used.
	UpdateWorkers int

	// If set to true, there will not be a goroutine launched to periodically
	// run updaters.
	DisableBackgroundUpdates bool

	// UpdaterConfigs is a map of functions for configuration of Updaters.
	UpdaterConfigs map[string]driver.ConfigUnmarshaler

	UpdaterFilter func(name string) (keep bool)

	// Client is an http.Client for use by all updaters. If unset,
	// http.DefaultClient will be used.
	Client *http.Client
}
```
The above outlines the relevant bits of the Opts structure.

### Construction
Constructing LibVuln is straight forward.

```go
opts := libvuln.Opts{
}

ctx := context.TODO()
lib, err := libvuln.New(ctx, opts)
if err != nil {
    log.Fatal(err)
}
```

The constructing code should provide a valid ctx tied to some lifetime.

On construction, New will block until the security databases are initialized. Expect some delay before this method returns.

### Scanning
Scanning is the process of taking a claircore.IndexReport comprised of a Manifest's content and determining which vulnerabilities affect the Manifest. A claircore.VulnerabilityReport will be returned with these details.

```go
m := Manifest{
...
}
ir, err := libindex.Index(ctx, m)
if err != nil {
    log.Fatal(err)
}

ctx := context.TODO()
ir, err := lib.Scan(ctx, ir)
if err != nil {
    log.Fatal(err)
}
```

In the above example LibIndex is used to generate a claircore.IndexReport. The index report is then provided to LibVuln and a subsequent vulnerability report identifying any vulnerabilities affecting the manifest is returned.

### Updates API
By default, LibVuln manages a set of long running updaters responsible for periodically fetching and loading new advisory contents into its database. The Updates API allows the a client to view and manipulate aspects of the update operations that updaters perform.

In this getting started guide, we will only cover the two methods most interesting to new users.

#### UpdateOperations
This API provides a list of recent update operations performed by implemented updaters. 
The UpdateOperation slice returned will be sorted by latest timestamp descending. 
```go
ops, err := lib.UpdateOperations(ctx)
if err != nil {
    log.Fatal(err)
}
for updater, ops := range ops {
    fmt.Printf("ops for updater %s, %+v", updater, ops)
}
```

#### UpdateDiff
Mostly used by ClairV4's notification subsystem, this endpoint will provide the caller with any removed or added vulnerabilities between two update operations. Typically a diff takes places against two versions of the same data source. This is useful to inform downstream applications what new vulnerabilities have entered the system.

```go
ops, err := lib.UpdateOperations(ctx)
if err != nil {
    log.Fatal(err)
}

diff, err := lib.UpdateDiff(ctx, ops[1].ID, ops[0].ID)
if err != nil {
    log.Fatal(err)
}
for _, vuln := range diff.Added {
    fmt.Printf("vuln %+v added in %v", vuln, diff.Cur.Ref)
}
```
