#!/bin/sh
MAJOR_VERSION=$1
CHECK_VERSION=$MAJOR_VERSION
CHECK_MINOR_VERSION=0

while true; do
    URL=https://dl.google.com/go/go${CHECK_VERSION}.linux-amd64.tar.gz
	code=$(curl -I -o /dev/null -s -w "%{http_code}\n" "$URL")
	printf '%s\t%d\n' "$URL" "$code" >&2
	case "$code" in
	200)
		OK="$CHECK_VERSION"
		CHECK_VERSION=${MAJOR_VERSION}.$((CHECK_MINOR_VERSION+=1))
		;;
	*)
		test -z "$OK" && exit 99
		echo "$OK"
		exit 0
		;;
	esac
done
