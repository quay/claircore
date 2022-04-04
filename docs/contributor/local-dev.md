# Local Development

A local development environment is implemented via docker-compose.  

# Usage

Several make targets are defined for working with the local development environment.  

```
{{# make_target claircore-db-up }} - creates just the claircore database useful for running integration tests without test servers
{{# make_target claircore-db-restart }} - destroys and recreates a fresh database. localhost:5434
```

# Tests

Several make targets are defined for working with tests.  

```
{{# make_target integration }} - run the integration test suite. requires the claircore-db to be up. run `make clair-db-up` before this target
{{# make_target unit }} - run the unit test suite.
{{# make_target bench }} -  runs the benchmarks
{{# make_target integration-v }} - runs the integration test suite with verbose
{{# make_target unit-v }} - runs the unit test suite with verbose
```
