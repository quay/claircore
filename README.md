![](https://github.com/quay/claircore/workflows/CI/badge.svg)
# ClairCore

ClairCore provides a set of go modules which handle scanning container layers for installed packages and reporting any discovered vulnerabilities.  
ClairCore is designed to be embedded into a service wrapper.  

For a full overview see: [ClairCore Book](https://quay.github.io/claircore)

# Local development and testing

The following targets start and stop a local development environment  
```
make local-dev-up
make local-dev-down
```

If you modify libvuln or libindex code the following make targets will restart the services with your changes  
```
make libindexhttp-restart
make libvulnhttp-restart
```

With the local development environment up the following make target runs all tests including integration  
```
make integration
```

The following make target runs unit tests which do not require a database or local development environment  
```
make unit
```
