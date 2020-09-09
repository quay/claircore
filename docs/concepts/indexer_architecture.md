# Indexer
`claircore/internal/indexer`  

The Indexer package performs LibIndex's heavy lifting. It is responsible for retreiving Manifest layers, parsing the contents of each layer, and computing an IndexReport.  

To perform this action in incremental steps the Indexer is implemented as a finite state machine. At each state transition the Indexer persists an updated IndexReport to its datastore.

## States
The following diagram expresses the possible states of the Indexer  
![indexer controller state diagram](./indexer_state_diagram.png "indexer controller state diagram")  

## Data Model
The Indexer data model focuses on content addressable hashes as primary keys, the deduplication of package/distribution/repostitory information, and the recording of scan artifacts.  
Scan artifacts are unique artifacts found within a layer which point to a deduplicated general package/distribution/repository record.  

The following diagram outlines the current Indexer data model.  
![indexer data model diagram](./indexer_data_model.png "indexer data model diagram")  

