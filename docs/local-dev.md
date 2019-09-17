# Local Development

A local development environment is implemented via docker-compose.  

# Usage

Several make targets are defined for working with the local development environment.  

```
local-dev-up - runs a db, libvulnhttp and libscanhttp
local-dev-logs - tails all aggregated container logs
local-dev-down - tears down the local development environment
claircore-db-restart - destroys and recreates a fresh database. localhost:5434
libscanhttp-restart - builds and runs libscanhttp with any new changes. localhost:8080
libvulnhttp-restart - builds and runs libvulnhttp with any new changes. localhost8081
claircore-db-up - creates just the claircore database useful for running integration tests
```

# Tests

Several make targets are defined for working with tests.  

```
integration - run the integration test suite. requires the claircore-db to be up. run `make clair-db-up` before this target
unit - run the unit test suite.
bench -  runs the benchmarks
integration-v - runs the integration test suite with verbose
unit-v - runs the unit test suite with verbose
```
