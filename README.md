![](https://github.com/quay/claircore/workflows/CI/badge.svg)
# Claircore

Claircore provides a set of go modules which handle scanning container layers for installed packages and reporting any discovered vulnerabilities.
Claircore is designed to be embedded into a service wrapper.

For a full overview see: [Claircore Book](https://quay.github.io/claircore)

# Testing

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

With the local development environment up the following make target runs all tests including integration with full benchmark results.
```sh
make bench
```
