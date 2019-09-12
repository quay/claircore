# Vulnerability Matching

This is a high level document expressing how we match packages in a particular package databse with vulnerabilities from a particular security tracker.  

## The Big Picture

### PackageScanner

PackageScanner(s) are the method for indexing discovered packages in a layer.  
It starts with the `claircore.internal.scanner.PackageScanner` interface.  
```
type PackageScanner interface {
	VersionedScanner
	// Scan performs a package scan on the given layer and returns all
	// the found packages
	Scan(*claircore.Layer) ([]*claircore.Package, error)
}

type VersionedScanner interface {
	// unique name of the distribution scanner.
	Name() string
	// version of this scanner. this information will be persisted with the scan.
	Version() string
	// the kind of scanner. currently only package is implemented
	Kind() string
}
```
The goals of a package scanner is to identify both package and distribution information from a layer.  
Distribution information is contextual details around a package. See claircore.Package and claircore.Distribution for more details.  
A layer may not have the necessary files to identify it's Distribution details.  
In this case returning empty distribution information is fine.  
However you must do your best to assertain this information.  
More on this in a bit.

### Updaters

Updater(s) are the method for indexing CVE data for matching.  
Implementing an updater involves two Interfaces.  
```
type Fetcher interface {
	// Fetch should retrieve the target vulnerability data and return an io.ReadCloser
	// with the contents. Fetch should also return a string which can used to determine
	// if these contents should be applied to the vulnerability database. for example
	// a sha265 sum of a OVAL xml file.
	Fetch() (io.ReadCloser, string, error)
}

type Parser interface {
	// Parse should take an io.ReadCloser, read the contents, parse the contents
	// into a list of claircore.Vulnerability structs and then return
	// the list. Parse should assume contents are uncompressed and ready for parsing.
	Parse(contents io.ReadCloser) ([]*claircore.Vulnerability, error)
}
```

The reason we split fetching and parsing is to easily support offline modes of operation.  
A parser can be provided any io.ReadCloser allowing for simple scripts to be implemented for on demand parsing and indexing of CVE data.  
In order to run your updater on an interval and as part of the claircore runtime you must implement both methods.  

### Matchers

Matcher(s) inform claircore exactly how to match packages to vulnerabilities  
Matcher interface looks like this  
```
type Matcher interface {
	// Interested informs the MatchController if implemented Matcher is interested in the
	// provided package.
	Interested(pkg *claircore.Package) bool
	// How informs the MatchController how it should match packages with vulnerabilities.
	// MatchSource tells the MatchController to use the package's source name when querying vulnerabilities.
	How() (MatchSource bool, Matchers []*vulnstore.Matcher)
	// Decide informs the MatchController if the given package is affected by the given vulnerability.
	// Typically this involves checking the "FixedInVersion" field.
	Decide(pkg *claircore.Package, vuln *claircore.Vulnerability) bool
}
```

An implemented Matcher must tell claircore if they are interested in a specific package.   
For instance a Ubuntu matcher maybe interested in a package if it's Distribution.Name == "Ubuntu".  

A Matcher must also tell us how to query the vulnerability database or as we call, the vulnstore.  
In order to do this the matcher must provide whether it's looking for the Binary package's name or it's affiliated source along with a list of vulnstore.Matcher structs.  
```
type Matcher int

const (
	Unknown Matcher = iota
	// should match claircore.Package.Source.Name => claircore.Vulnerability.Package.Name
	PackageSourceName
	// should match claircore.Package.Name => claircore.Vulnerability.Package.Name
	PackageName
	// should match claircore.Package.Distribution.DID => claircore.Vulnerability.Package.Distribution.DID
	PackageDistributionDID
	// should match claircore.Package.Distribution.Name => claircore.Vulnerability.Package.Distribution.Name
	PackageDistributionName
	// should match claircore.Package.Distribution.Version => claircore.Vulnerability.Package.Distribution.Version
	PackageDistributionVersion
	// should match claircore.Package.Distribution.VersionCodeName => claircore.Vulnerability.Package.Distribution.VersionCodeName
	PackageDistributionVersionCodeName
	// should match claircore.Package.Distribution.VersionID => claircore.Vulnerability.Package.Distribution.VersionID
	PackageDistributionVersionID
	// should match claircore.Package.Distribution.Arch => claircore.Vulnerability.Package.Distribution.Arch
	PackageDistributionArch
)
```
Providing multiple vulnstore.Matcher structs logically "ANDs" them together.  
It is our assumption that implementors of Updaters will also implement Matchers.  
The implementor knows the details of how CVE data is indexed, what fields the CVE data uses for package identification, and whether CVE data references source or binary package names.  

## An end to end success

A successful scan looks like this:  

1. updaters have ran either in the background on an interval or have had their Parse methods called and offline-loaded CVE data into the vulnstore
2. a manifest is provided to libscan. libscan fetches all the layers, stacks the image like a container runtime would, and runs each `claircore.internal.scanner.PackageScanner` on each layer.
3. libscan indexes all the packages found by each scanner and creates the necessary relations. a ScanReport is persisted to libscan's database summarizing what was found.
4. a client request is made to libvuln. libvuln retrieves the ScanReport from libscan. libscan maybe running alongside libvuln in process or may be distributed the library is designed for modularity.
5. libvuln concurrently creates all the configured Matchers and feeds them the packages summarized in the claircore.ScanReport.
6. libvuln collects all the matched vulnerabilities returned from each Matcher and creates a request scoped claircore.VulnerabilityReport. this is returned to the client
7. sometime later the vulnstore is updated. the next time a client asks for a response from libvuln a new claircore.VulnerabilityReport is generated. no caching or peristence takes place.

## The scanning process

Scanning is implemented in the `claircore.internal.scanner.defaultscanner` package and is implemented as an FSM to support easy changes in operation.  
The default scanner works as follows:  

1. Determines if the manifest should be scanned. It will be scanned if we've never seen the manifest's hash or if we detect a new scanner is preset which has not scanned said manifest
2. The manifest's layers are then fetched and written to disk. The Moby Framework is then used to stack the layers giving us an accurate depiction of the filesystem at runtime. 
3. Each layer is scanned for packages by the configured PackageScanner(s). Discovered pages are indexed into the database with a simple relation tying together Package, Distribution, and Scanner which found them
4. The scanner asks for all the packages found in the stacked layer first. These are the packages we focus on and are the ones actually remaining on the runtime file system.
5. Next we ask for all the packages found in layers 0...N serially. If we come across a package which exists in the stacked image we record the **first** encounter of this package. This is the layer that introduced said package.
7. Finally we call a special method on the store which performs a transaction breaking idempotency of a scan. After this method runs the next time the scanner sees the manifest hash it will not be scanned unless the last condition in step 1 is present. If the transaction were to fail the work that was done scanning layers is not lost however the scan should be replayed to ensure a ScanReport is persisted.

## The vulnerability matching process

Matching vulnerabilities is facilitated by methods in the `claircore.internal.vulnstore`, `claircore.internal.matcher`, and `claircore.internal.vulnscanner` packages. They process looks like this:  

1. libvuln is instantiated and configured with a set of `claircore.internal.matcher` implementations. 
2. lubvuln gets a request to find vulnerabilities for a manifest. first it reaches out to libscan to retrieve the ScanReport
3. with the ScanReport retrieved a `claircore.internal.vulnscanner.VulnScanner` is created.
4. the VulnScanner launches all configured Matcher(s) by way of a MatchController. The MatchController drives the Matcher(s) calling the appropriate functions and handling results and errors
5. the VulnScanner dedupes and merges all vulnerabilities discovered by MatchControllers and returns a VulernabilityReport
