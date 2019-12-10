# ClairCore

ClairCore provides a set of go modules which handle scanning container layers for installed packages and reporting any discovered vulnerabilities.  
ClairCore is designed to be embedded into a service wrapper.  

# Usage

Two packages exist `libindex` and `libvuln`.  
These modules export the methods for scanning and image for packages and matching the results of the scan to vulnerabilities respectively.   

## libindex usage

Creating an instance  
```
opts := &libindex.Opts{
    DataStore: libindex.Postgres,
    ConnString: "postgres://host:port",
    ScanLock: libindex.PostgresSL,
    // see definition for more configuration options
}
lib := libindex.New(opts)
``` 
call libindex with a populated Manifest  
```
m := &claircore.Manifest{
    ...
}

ir, err := lib.Index(m)
if err != nil {
    log.Printf("%v", err)
}
if ir.State == "ScanError" {
    log.Printf("scan failed: %s", sr.Err)
}
```

## libvuln usage
```
creating an instance  
```
opts := &libvuln.Opts{
    DataStore: libvuln.Postgres,
    ConnString: "postgres://host:port",
    ScanLock: libindex.PostgresSL,
    // see definition for more configuration option
}
lib := libvuln.New(opts)
```
call libvuln with a populated IndexReport  
```
sr := &claircore.IndexReport{
    ...
}
vr, err := libvuln.Scan(sr)
if err != nil {
    log.Printf("%v", err)
}
```

Libvuln will first initialize all updaters before returning from its constructor.  
Controlling how many updaters initialize in parallel is provided via the libvuln.Opts struct  

# Local development and testing

The included makefile has targets for spawning a libindex and a libvuln database instance.  
```
make libindex-db-restart
make libvuln-db-restart
```

After both targets are ran you may run integration tests  
```
make integration
```

unit tests do not require a database  
```
make unit
```

## Dev servers

ClairCore provides two http servers for local development and quick testing/hacking.  
You may build these from `./cmd/libindexhttp` and `./cmd/libvulnhttp`  

## Running libindex on darwin/MacOS

Layer stacking will fail on Darwin/MacOS with a file permissions issue and subsequently fail the scanner.   
In order to get around this the layer stacking integration test has a build tag "unix".  
The makefile target `integration-unix` runs tests that will only pass on a unix env.   
You may use the make target 'docker-shell' to drop into a linux shell where `make integration-unix` may be ran.  

# Deeper dives

[Highlevel Architecture](./docs/highlevel_arch.md)  
[Matching Architecture](./docs/matching_arch.md)  
[Vulnerability Matching](./docs/matching_vulns.md)  
[Vulnerability Tombstoning](./docs/tombstoning.md)  
[Content-Addressability](./docs/content_addressability.md)  
[Libindex Data Model](./docs/scanner_data_model.md)  
[Indexer States](./docs/indexer_states.md)  
[Local Development](./docs/local-dev.md)  
