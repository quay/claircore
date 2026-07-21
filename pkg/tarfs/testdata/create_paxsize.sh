#!/bin/sh
set -eu
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
out="$PWD/testdata/paxsize.tar"
(
	cd "$d"
	touch normalfile
	tar \
		--create \
		--format=pax \
		--group=glenda:1000 \
		--owner=glenda:1000 \
		--mtime="$(date --date @0 -u -Iseconds)" \
		--pax-option=size:=1024 \
		--add-file=normalfile \
		> "$out"
)
truncate -s +1024 "$out"
