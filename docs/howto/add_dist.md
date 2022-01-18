# Adding Distribution And Language Support

*Note: If terms in this document sound foreign check out [Getting Started](../getting_started.md) to acquaint yourself with "indexing", "scanning", and "matching"*

The claircore team is always open to adding more distributions and languages to the library.

Generally, distributions or languages must provide a security tracker. 

All officially supported distributions and languages provide a database of security vulnerabilities. 

These databases are maintained by the distribution or language developers and reflect up-to-date CVE and advisory data for their packages.

If your distribution or language does not provide a security tracker or piggy-backs off another distribution's start an issue in our Github issue tracker to discuss further.

## Implementing an Updater

The first step to adding your distribution or language to claircore is getting your security tracker's data ingested by Libvuln. 

The Updater interfaces are responsible for this task.

An implementer must consider several design points:
* Does the security database provide enough information to parse each entry into a claircore.Vulnerability?
    * Each entry must parse into a claircore.Vulnerability. 
    * Each Vulnerability **must** contain a package **and** a repository **or** distribution field. 
* Will the Updater need to be configured at runtime?
    * Your updater may implement the Configurable interface. Your matcher will have its "Configuration" method called before use, giving you an opportunity for run time configuration.
* What fields in a parsed claircore.Vulnerability will be present when indexing layer artifacts.
    * When implementing an updater you must keep in mind how packages/distributions/repositories will be parsed during index.
	  When indexing a layer a common data model **must** exist between the possible package/distribution/repository and the parsed Vulnerabilitie's package/distribution/repository fields.

If you are having trouble figuring out these requirements do not hesitate to reach out to us for help. 

After you have taken the design points into consideration, you are ready to implement your updater.

Typically you will create a new package named after the source you are adding support for. 

Inside this package you can begin implementing the [Updater](../reference/updater.md) and [Updater Set Factory](../reference/updatersetfactory.md) interfaces.

Optionally you may implement the [Configurable](../reference/updater.md) interface if you need runtime configuration.

It will undoubtly be helpful to look at the examples in the "ubuntu", "rhel", and "debian" packages to get yourself started.

## Implementing a Package Scanner

At this point you hopefully have your Updater working, writing vulnerability data into Libvuln's database. 

We can now move our attention to package scanning.

A package scanner is responsible for taking a claircore.Layer and parsing the contents for a particular package database or set of files inside the provided tar archive.
Once the target files are located the package scanner should parse these files into claircore.Packages and return a slice of these data structures. 

Package scanning is context free, meaning no distribution classification has happened yet.
This is because manifests are made up of layers, and a layer which holds a package database may not hold distribution information such as an os-release file.
A package scanner need only parse a target package database and return claircore.Packages.

You need to implement the [Package Scanner](../reference/packagescanner.md) interface to achieve this.

Optionally, you may implement the [Configurable Scanner](../reference/configurable_scanner.md) if the scanner needs to perform runtime configuration before use.

Keep in mind that its very common for distributions to utilize an existing package manager such as RPM. 

If this is the case there's a high likelihood that you can utilize the existing "rpm" or "dpkg" package scanner implementations.

## Implementing a Distribution Scanner

Once the package scanner is implemented, tested, and working you can begin implementing a Distribution Scanner.

Implementing a distribution scanner is a design choice.
Distributions and repositories are the way claircore matches packages to vulnerabilities. 

If your implemented Updater parses vulnerabilities with distribution information you will likely need to implement a distribution scanner.
Likewise, if your Updater parses vulnerabilities with repository information (typical with language vulnerabilities) you will likely need to implement a repository scanner.

A distribution scanner, like a package scanner, is provided a claircore.Layer. 

The distribution scanner will parse the provided tar archive exhaustively searching for any clue that this layer was derived from your distribution.
If you identify that it is, you should return a common distribution used by your Updater implementation.
This ensures that claircore can match the output of your distribution scanner with your parsed vulnerabilities. 

Optionally, you may implement the [Configurable Scanner](../reference/configurable_scanner.md) if the scanner needs to perform runtime configuration before use.

## Implementing a Repository Scanner

As mentioned above, implementing a repository scanner is a design choice, often times applicable for language package managers.

If your Updater parses vulnerabilities with a repository field you will likely want to implement a repository scanner.

A repository scanner is used just like a distribution scanner however you will search for any clues that a layer contains your repository and if so return a common data model identifying the repository.

Optionally, you may implement the [Configurable Scanner](../reference/configurable_scanner.md) if the scanner needs to perform runtime configuration before use.

## Implementing a Coalescer

As you may have noticed, the process of scanning a layer for packages, distribution, and repository information is distinct and separate.

At some point, claircore will need to take all the context-free information returned from layer scanners and create a complete view of the manifest.
A coalescer performs this computation. 

It's unlikely you will need to implement your own coalescer.
Claircore provides a default "linux" coalescer which will work if your package database is rewritten when modified.
For example, if a Dockerfile's `RUN` command causes a change to to dpkg's `/var/lib/dpkg/status` database, the resulting manifest will have a copy placed in the associated layer.

However, if your package database does not fit into this model, implementing a coalescer may be necessary.

To implement a coalescer, several details must be understood:
* Each layer only provides a "piece" of the final manifest.
    * Because manifests are comprised of multiple copy-on-write layers, some layers may contain package information, distribution information, repository information, any combination of those, or no information at all.
* An OS may have a "dist-upgrade" performed and the implications of this on the package management system is distribution or language dependent.
    * The coalescer must deal with distribution upgrades in a sane way.
	  If your distribution or language does a dist-upgrade, are all packages bumped?
	  Are they simply left alone?
	  The coalescer must understand what happens and compute the final manifest's content correctly.
* Packages may be removed and added between layers.
    * When the package database is a regular file on disk, this case is simpler: the database file found in the most recent layer holds the ultimate set of packages for all previous layers.
	  However, in the case where the package database is realized by adding and removing files on disk it becomes trickier.
	  Claircore has no special handling of whiteout files, currently.
	  We will address this in upcoming releases.

If your distribution or language cannot utilize a default coalescer, you will need to implement the [Coalescer interface](../reference/coalescer.md)

## Implementing or Adding To An Ecosystem

An Ecosystem provides a set of coalescers, package scanners, distribution scanners, and repository scanners to Libindex at the time of indexing.

Libindex will take the [Ecosystem](../reference/ecosystem.md) and scan each layer with all provided scanners.
When Libindex is ready to coalesce the results of each scanner into an [IndexReport](../reference/index_report.md) the provided coalescer is given the output of the configured scanners.

This allows Libindex to segment the input to the coalescing step to particular scanners that a coalescer understands. 

For instance, if we only wanted a (fictitious) Haskell coalescer to evaluate artifacts returned from a (fictitious) Haskell package and repository scanner we would create an ecosystem similar to:

```go
{{#include ../howto_test.go:example}}
```
This ensures that Libindex will only provide Haskell artifacts to the Haskell coalescer and avoid calling the coalescer with rpm packages for example.

If your distribution uses an already implemented package manager such as "rpm" or "dpkg", it's likely you will simply add your scanners to the existing ecosystem in one of those packages.

## Alternative Implementations

This how-to guide is a "perfect world" scenario.

Working on claircore has made us realize that this domain is a bit messy.
Security trackers are not developed with package managers in mind, security databases do not follow correct specs, distribution maintainers spin their own tools, etc.

We understand that supporting your distribution or language may take some bending of claircore's architecture and business logic.
If this is the case, start a conversation with us.
We are open to design discussions.

## Getting Help

At this point, you have implemented all the necessary components to integrate your distribution or language with claircore.

If you struggle with the design phase or are getting stuck at the implementation phases do not hesitate to reach out to us.
Here are some links:

- [Clair SIG](https://groups.google.com/g/clair-dev?pli=1)
- [Github Issues](https://github.com/quay/claircore)
- [RedHat Issues](https://issues.redhat.com/projects/PROJQUAY)
