# Red Hat Container-First Content


|            |          |
|:-----------|:---------|
|Indexer Type|`package` |
|Indexer Name|`rhcc`    |
|Updater Name|`rhel-vex`|
|Matcher Name|`rhcc`    |

Red Hat Container-First Content is supported by looking for a manifest file at
`root/buildinfo/labels.json` inside container layers and treating the discovered
information as a Package.

## JSON Schema

This is the [JSON Schema] that files discovered at `root/buildinfo/labels.json`
are expected to conform to:

```
{{#include ../../rhel/rhcc/testdata/labels.schema.json}}
```

[JSON Schema]: https://json-schema.org/
