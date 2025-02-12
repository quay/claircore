# shellcheck shell=sh

pathmunge /usr/local/go/bin

if [ "$(hostname)" == toolbox ]; then
	HOSTNAME="$(. /run/.containerenv && echo "$name")"
	export HOSTNAME HOST="$HOSTNAME"
	sudo hostname "${HOSTNAME}" || :
fi
