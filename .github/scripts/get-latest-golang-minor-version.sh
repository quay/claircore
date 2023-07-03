#!/bin/sh
MAJOR_VERSION=${1?missing required argument: language version}
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
		# Account for version scheme change. See issue #991.
		if test -z "$(echo "${CHECK_VERSION}" | cut -d . -f 3 2>/dev/null)"; then
			CHECK_VERSION=${MAJOR_VERSION}.${CHECK_MINOR_VERSION}
			continue
		fi
		test -z "$OK" && exit 99
		echo "$OK"
		exit 0
		;;
	esac
done
