# Claircore
[![Build Status](https://github.com/quay/claircore/actions/workflows/main.yml/badge.svg)](https://github.com/quay/claircore/actions/workflows/main.yml)
[![GoDoc](https://pkg.go.dev/badge/github.com/quay/claircore?status.svg)](https://pkg.go.dev/github.com/quay/claircore)
[![codecov](https://codecov.io/github/quay/claircore/coverage.svg?branch=main)](https://codecov.io/github/quay/claircore?branch=main)

A container security library from Red Hat's Clair and Advanced Cluster Security teams.q 

For a full overview see: [Claircore Book](https://quay.github.io/claircore)

Claircore is a library that provides scanning container layers for installed packages
and reporting any discovered vulnerabilities.

## Quick start

### Requirements

There some things claircore needs:
- A datastore. Claircore contains a PostgreSQL implementation out of the box.
- Enough storage for the images you intend to scan.

### Basic components

Claircore's main entire points are:
- `libindex`: The module that indexes packages and reports all packages for each layer.
- `libvuln`: The module that matches vulnerabilities using an index report.

## Development

### Testing

The following make target runs unit tests which do not require a database or local development environment.
```sh
make unit
# or make unit-v for verbose output
```

With the local development environment up the following make target runs all tests including integration.
```sh
make integration
# or integration-v for verbose output
```

With the local development environment up the following make target runs all tests including integration with full
benchmark results.
```sh
make bench
```
