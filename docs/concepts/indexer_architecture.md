# Indexer
`claircore/indexer`

The Indexer package performs Libindex's heavy lifting. It is responsible for retreiving Manifest layers, parsing the contents of each layer, and computing an IndexReport.

To perform this action in incremental steps the Indexer is implemented as a finite state machine. At each state transition the Indexer persists an updated IndexReport to its datastore.

## States
The following diagram expresses the possible states of the Indexer:
```mermaid
stateDiagram-v2
	state if_indexed <<choice>>
	[*] --> CheckManifest
	CheckManifest --> if_indexed
	if_indexed --> [*]: Indexed
	if_indexed --> FetchLayers: Unindexed
	FetchLayers --> ScanLayers
	ScanLayers --> Coalesce
	Coalesce --> IndexManifest
	IndexManifest --> IndexFinished
	IndexFinished --> [*]
%% These notes make the diagram unreadable :/
%% note left of CheckManifest: Determine if this manifest has been indexed previously.
%% note right of FetchLayers: Determine which layers need to be indexed and fetch them.
%% note right of ScanLayers: Concurrently run needed Indexers on layers.
%% note right of Coalesce: Compute the final contents of the container image.
%% note right of IndexManifest: Associate all the discoved data.
%% note right of IndexFinished: Persist the results.
```

## Data Model
The Indexer data model focuses on content addressable hashes as primary keys, the deduplication of package/distribution/repostitory information, and the recording of scan artifacts.
Scan artifacts are unique artifacts found within a layer which point to a deduplicated general package/distribution/repository record.

The following diagram outlines the current Indexer data model.
```mermaid
%%{init: {"er":{"layoutDirection":"RL"}} }%%
erDiagram
	ManifestLayer many to 1 Manifest: ""
	ManifestLayer many to 1 Layer: ""
	ScannedLayer many to 1 Layer: ""
	ScannedLayer many to 1 Scanner: ""
	ScannedManifest many to 1 Manifest: ""
	ScannedManifest many to 1 Scanner: ""

	TYPE_ScanArtifact 1 to 1 Layer: ""
	TYPE_ScanArtifact 1 to 1 Scanner: ""
	TYPE_ScanArtifact 1 to 1 TYPE: ""

	ManifestIndex many to 1 Manifest: ""
	ManifestIndex 1 to zero or one TYPE: ""

	IndexReport 1 to 1 Manifest: "cached result"
```
Note that `TYPE` stands in for each of the Indexer types (i.e. `Package`, `Repository`, etc.).

## HTTP Resources

Indexers as currently built may make network requests.
This is an outstanding issue.
The following are the URLs used.

{{# injecturls indexer }}
