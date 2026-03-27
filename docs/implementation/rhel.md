# Red Hat-built Linux

`Rhel` is our term for container images made from Linux distributions made by
Red Hat, such as Enterprise Linux, Universal Base Image, CoreOS, and Hardened
Images.

|            |                      |
|:-----------|:---------------------|
|Indexer Type|`package`             |
|Indexer Name|`rhel-package-scanner`|
|Updater Name|`rhel-vex`            |
|Matcher Name|`rhel`                |
> [!WARNING]
> Claircore does not support [dynamic modules] because doing so would require
> online access to the `dnf` repository a package came from every time a
> VulnerabilityReport is requested.

|            |                         |
|:-----------|:------------------------|
|Indexer Type|`repository`             |
|Indexer Name|`rhel-repository-scanner`|
|Updater Name|N/A                      |
|Matcher Name|`rhel`                   |
> [!WARNING]
> Repository support requires additional metadata loaded into the indexer
> process. See the [`github.com/quay/claircore/rhel`][godoc] package documentation for
> more information.

|            |              |
|:-----------|:-------------|
|Indexer Type|`distribution`|
|Indexer Name|`rhel`        |
|Updater Name|N/A           |
|Matcher Name|N/A           |

`Rhel` images are supported by examining `rpm` and `dnf` databases as needed.

[dynamic modules]: https://docs.fedoraproject.org/en-US/modularity/core-concepts/upgrade-paths/#_dynamic_context
[godoc]: https://pkg.go.dev/github.com/quay/claircore/rhel
