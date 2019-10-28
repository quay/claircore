# Scanner States
The `internal/scanner/controller` package implements a state machine for scanning a manifest.  
Each layer is individually scanned and the discovered artifacts are indexed into the database.  
A `Coalescer` is then used to create platform specific coalesced image views from their discrete layers.A ScanReport is populated with all packages found in the **final** container image expressed by the manifest. 

# Scan Controller States
![alt text](./scanner_state_diagram.png "scan controller state diagram")
