#!/bin/sh
set -ex
trap 'for i in `seq 3`; do find . -empty -delete; done' EXIT
seq 7 99 | while read v; do
	mkdir -p dist/$v/etc
	podman run --rm docker.io/library/debian:$v cat /etc/os-release > dist/$v/etc/os-release ||
		exit 0
done
