[![Build Status](https://cloud.drone.io/api/badges/quay/claircore/status.svg)](https://cloud.drone.io/quay/claircore)  
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
    ConnString: "postgres://host:port",
    Migrations: true,
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
if ir.State == "IndexError" {
    log.Printf("scan failed: %s", sr.Err)
}
```

## libvuln usage

creating an instance  
```
opts := &libvuln.Opts{
    ConnString: "postgres://host:port",
    Migrations: true,
    // see definition for more configuration option
}
lib := libvuln.New(opts)
```
call libvuln with a populated IndexReport  
```
ir := &claircore.IndexReport{
    ...
}
vr, err := libvuln.Scan(ir)
if err != nil {
    log.Printf("%v", err)
}
```

Libvuln will first initialize all updaters before returning from its constructor.  
Controlling how many updaters initialize in parallel is provided via the libvuln.Opts struct  

# Local development and testing

The following targets start and stop a local development environment
```
make local-dev-up
make local-dev-down
```

If you modify libvuln or libindex code the following make targets will restart the services with your changes
```
make libindexhttp-restart
libvulnhttp-restart
```

With the local development environment up the following make target runs all tests including integration
```
make integration
```

The following make target runs unit tests which do not require a database or local development environment
```
make unit
```

# Deeper dives

[Highlevel Architecture](./docs/highlevel_arch.md)  
[Matching Architecture](./docs/matching_arch.md)  
[Vulnerability Matching](./docs/matching_vulns.md)  
[Vulnerability Tombstoning](./docs/tombstoning.md)  
[Content-Addressability](./docs/content_addressability.md)  
[Libindex Data Model](./docs/scanner_data_model.md)  
[Indexer States](./docs/indexer_states.md)  
[Local Development](./docs/local-dev.md)  
