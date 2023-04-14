#!/bin/sh
# Importfix is a helper to keep a consistent import style.
#
# This is unneeded if your editor is configured to group imports with this module as the local prefix.
#
# By default, only files in the current commit are modified.
# If an argument is provided, it's used as a revset to list files from.
set -e
cd "$(git rev-parse --show-toplevel)"
mod="$(go list -m)"
goimports=$(command -v goimports || echo go run golang.org/x/tools/cmd/goimports@latest)
git show --pretty=format: --name-only "${1:-HEAD}" -- ':*\.go' | (
	while read -r f; do
		sed -i'' '/import (/,/)/{ /^$/d }' "$f"
		$goimports -local "$mod" -w "$f"
	done
)
