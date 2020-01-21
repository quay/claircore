# Cctool
`Cctool` is a small utility to make poking at claircore components easier.

## Build
Build via the standard incantation:
```
go build ./cmd/cctool
```

## Usage
`Cctool` is driven by subcommands. Use the "h" flag before a subcommand to see
common flags and a list of subcommands. Use the "h" flag after a subcommand to
see flags specific to that subcommand.

### Report
The `report` subcommand reads in docker-like image references on the command
line or stdin and outputs a column-oriented summary, suitable for passing to a
tool like `awk`.

`Report` expects to talk to the development HTTP servers.

### Manifest
The `manifest` subcommand reads in docker-like image references on the command
line or stdin and outputs newline-separated json manifests, suitable for passing
to libindex.
