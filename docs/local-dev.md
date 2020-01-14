# Local Development

A local development environment is implemented via docker-compose.  

# Usage

Several make targets are defined for working with the local development environment.  

```
local-dev-up - runs a db, libvulnhttp and libindexhttp
local-dev-logs - tails all aggregated container logs
local-dev-down - tears down the local development environment
claircore-db-up - creates just the claircore database useful for running integration tests without test servers
claircore-db-restart - destroys and recreates a fresh database. localhost:5434
libindexhttp-restart - builds and runs libindexhttp with any new changes. localhost:8080
libvulnhttp-restart - builds and runs libvulnhttp with any new changes. localhost8081
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
