# Adding Distribution And Language Support

*Note: If terms in this document sound foreign check out [Getting Started](../getting_started.md) to acquaint yourself with "indexing", "scanning", and "matching"*

The ClairCore team is always open to adding more distributions and languages to the library.

Generally, distributions or languages must provide a security tracker. 

All officially supported distributions and languages provide a database of security vulnerabilities. 

These databases are maintained by the distribution\language developers and reflect up-to-date CVE and advisory data for their packages.

If your distribution\language does not provide a security tracker or piggy-backs off another distribution's start an issue in our Github issue tracker to discuss further.

## Implementing an Updater

The first step to adding your distribution or language to ClairCore is getting your security tracker's data ingested by LibVuln. 

The Updater interfaces are responsible for this task.

An implementor of an Updater must consider several design points.
* Does the security database provide enough information to parse each entry into a claircore.Vulnerability?
    * Each entry must parse into a claircore.Vulnerability. 
    * Each Vulnerability **must** contain a package **and** a repository **or** distribution field. 
* Will the Updater need to be configured at runtime?
    * Your updater may implement the Configurable interface. Your matcher will have its "Configuration" method called before use, giving you an opportunity for run time configuration.
* What fields in a parsed claircore.Vulnerability will be present when indexing layer artifacts.
    * When implementing an updater you must keep in mind how packages/distributions/repositories will be parsed during index. When indexing a layer a common data model **must** exist between the possible package/distribution/repository and the parsed Vulnerabilitie's package/distribution/repository fields.

If you are having trouble figuring out these requirements do not hesitate to reach out to us for help. 

After you have take the design points into consideration you are ready to implement your Matcher.

Typically you will create a new package named after the distribution\language you are adding support for. 

Inside this package you can begin implementing the [Updater interface](../reference/updater.md) and provide us an [Updater Set Factory](../reference/updatersetfactory.md) for runtime construction.

Optionally you may implement the [Configurable](../reference/updater.md) interface if you need runtime configuration.

It will undoubtly be helpful to look at the examples in the "ubuntu", "rhel", and "debian" packages to get yourself started.

## Implementing a Package Scanner

At this point you hopefully have your Updater working, writing vulnerability data into LibVuln's database. 

We can now move our attention to package scanning.

A package scanner is responsible for taking a claircore.Layer, getting a tarball handle to its contents, and parsing the contents for a particular package database or set of files on the file systems. Once the target files are located the package scanner should parse these files into claircore.Packages and return a slice of these data structures. 

Package scanning is context free, meaning no distribution classification has to happen yet. This is because containers are made up of layers and a layer which holds a package database may not hold distribution information such as an os-release file. A package scanner need only parse a target package database and return claircore.Packages.

You will implement the [Package Scanner](../reference/packagescanner.md) interface to achieve this.

Optionally you may implement the [Configurable Scanner](../referrence/configurable_scanner.md) if the scanner needs to perform run-time configuration before use.

Keep in mind that its very common for distributions to utilize an existing package manager such as RPM. 

If this is the case there's a high likelihood that you can utilize the existing "rpm" or "dpkg" package scanner implementations.

## Implementing a Distribution Scanner

Once the package scanner is implemented, tested, and working you can begin implementing a Distribution Scanner.

Implementing a distribution scanner is a design choice. Distributions as well as repositories implement the way ClairCore matches packages => vulnerabilities. 

If your implemented Updater parses vulnerabilities with distribution information you will likely need to implement a distribution scanner. Likewise if your Updater parses vulnerabilities with repository information (typical with language vulnerabilities) you will likely need to implement a repository scanner.

A distribution scanner, similarily to a package scanner, is provided a claircore.Layer which a tarball handle can be retrieved. 

The distribution scanner will parse the tarball exhaustively searching for any clue that this layer was derived from your distribution. If you identify that it is you should return a common distribution data model used by your Updater implementation. This ensures that ClairCore can match the ouput of your distribution scanner with your parsed vulnerabilities. 

You will implement the [Distribution Scanner](../reference/distribution_scanner.md) if your design mandates.

Optionally you may implement the [Configurable Scanner](../referrence/configurable_scanner.md) if the scanner needs to perform run-time configuration before use.

## Implementing a Repository Scanner

As mentioned above implementing a repository scanner is a design choice, often times applicable for language pacakge managers (not always, RHEL uses a repo scanner).

If your Updater parses vulnerabilities with a repository field you will likely want to implement a repository scanner.

A repository scanner is used just like a distribution scanner however you will search for any clues that a layer contains your repository and if so return a common data model identifying the repository.

You will implement the [Repository Scanner](../reference/repository_scanner.md) if your design mandates.

Optionally you may implement the [Configurable Scanner](../referrence/configurable_scanner.md) if the scanner needs to perform run-time configuration before use.

## Implementing a Coalescer

As you may have noticed the process of scanning a layer for packages, distribution, and repository information is distinct and saparate.

At some point ClairCore will need to take all the artifacts (a term we use for package/distribution/repository information) found in all the layers and compute a final "image" view. A coalescer performs this computation. 

Its unlikely you will need to implement your own coalescer. ClairCore provides a default "linux" coalescer which will work if your package database is a single, parsable, regular file on the file system. 

However if your package database does not fit into this model implementing a Coalescer maybe necessary.

To implement a Coalescer several details must be understood
* Each layer only provides a "piece" of the final image's data.
    * Because images are comprised of multiple sharable layers some layers may contain only package information, only distribution information, only respository information, no information at all, or any combination of these.
* An image may have a "dist-upgrade" performed and the implications of this on the package management system is distribution\lanaguge dependent
    * The coalescer must deal with distribution upgrades in a sane way. If your distrubtion\language does a dist-upgrade are all packages bumped? Are they simply left alone? The coalescer must understand what happens and compute the final image's content correctly.
* Packages maybe removed and added between layers
    * When the package database is a parsesable regular file on disk this case is simpler, the database file found in the most recent layer holds the ultimate set of packages in the image. However in the case where the package database is realized by several sets of file on disk it becomes a bit tricker. ClairCore does not support parsing white out files as "removals" currently. We will address this in upcoming releases. 

If your distribution or language cannot utilize a default coalescer you will need to implement the [Coalescer interface](../reference/coalescer.md)

## Implementing or Adding To An Ecosystem

An Ecosystem provides a set of coalescers, package scanners, distribution scanners, and repository scanners to LibIndex at time of indexing.

LibIndex will take the [Ecosystem](../reference/ecosystem.md) and scan each layer with all provided scanners. When LibIndex is ready to coalesce the results of each scanner into an [IndexReport](../reference/index_report.md) the provided coalescer is only given the out of the configured scanners.

This allows LibIndex to granularly segment off scanning and coalescing to a particular ecosystem. 

For instance if we only wanted a (fictitious) Haskell coalescer to evaluate artifacts returned from a Haskell package and repository scanner we would create an ecosystem similar to:

```go
// NewEcosystem provides the set of scanners and coalescers for the haskell ecosystem
func NewEcosystem(ctx context.Context) *indexer.Ecosystem {
	return &indexer.Ecosystem{
		PackageScanners: func(ctx context.Context) ([]indexer.PackageScanner, error) {
			return []indexer.PackageScanner{
                &haskell.Scanner{},
            }, nil
		},
		DistributionScanners: func(ctx context.Context) ([]indexer.DistributionScanner, error) {
			return []indexer.DistributionScanner{
			}, nil
		},
		RepositoryScanners: func(ctx context.Context) ([]indexer.RepositoryScanner, error) {
			return []indexer.RepositoryScanner{}, nil
		},
		Coalescer: func(ctx context.Context) (indexer.Coalescer, error) {
			return haskell.NewCoalescer(), nil
		},
	}
}
```
This ensures that LibIndex will only provide Haskell artifacts to the Haskell coalescer and avoid calling the coalescer with rpm packages for example.

If your distribution piggy backs on an already implemented package manager such as "rpm" or "dpkg" its likely you will simply add your scanners to the existing ecosystem in one of those packages.

## Alternative Implementations

This how-to guide is a "perfect world" scenario.

Working on ClairCore has made us realize that this domain is a bit messy. Security trackers are not developed with package managers in mind, security databases do not follow correct specs, distro maintainers spin their own tools, etc...

We understand that supporting your distribution\language may take some bending of ClairCore's architecture and business logic. If this is the case start a conversation with us. We are open to design discussions.

## Getting Help

At this point you have implemented all the necessary components to integrate your distribution or language with ClairCore.

If you struggle with the design phase or are getting stuck at the implementation phases do not hesitate to reach out to use. Here are some links:

[Clair SIG](https://groups.google.com/g/clair-dev?pli=1)
[Github Issues](https://github.com/quay/claircore)
[RedHat Issues](https://issues.redhat.com/projects/PROJQUAY)
