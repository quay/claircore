#!/bin/sh
curl -sSLf 'https://api.launchpad.net/devel/ubuntu/series' |
	jq -r '
		.entries[]|
		{name, version}|
		@sh "mkdir -p dist/\(.version)/etc",
		@sh "podman run --rm docker.io/library/ubuntu:\(.name) cat /etc/os-release>dist/\(.version)/etc/os-release",
		@sh "podman run --rm docker.io/library/ubuntu:\(.name) cat /etc/lsb-release>dist/\(.version)/etc/lsb-release",
		@sh "podman rmi docker.io/library/ubuntu:\(.name)"
	' |
	sh -x
for i in `seq 3`; do
	find . -empty -delete
done
