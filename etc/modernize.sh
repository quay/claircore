#!/usr/bin/zsh
emulate -L zsh
set -euo pipefail

local dryrun=0
local cmdpath="golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest"
local passes=( forvar slicescontains minmax sortslice efaceany mapsloop fmtappendf testingcontext omitzero bloop rangeint stringsseq stringscutprefix waitgroup )

function modernize() {
	pushd -q "${1?missing argument: package directory}"
	TRAPEXIT() {
		popd -q
	}
	local name=$(go list -f '{{.Name}}' .)
	print : package: "$1" >&2
	for p in "${(@)passes}"; do
		go run "$cmdpath" -fix -test -category "$p" .
		if ! git diff --exit-code &>/dev/null ; then
			if [[ dryrun != 0 ]]; then
				git commit --all --signof --message "${name}: modernize: ${p}"
			else
				print git commit --all --signof --message "${name}: modernize: ${p}"
				git diff -- .
				git checkout -- .
			fi
		fi
	done
}

local pkgs=( $(go list -f '{{.Dir}}' "${1:-./...}" 2>/dev/null || :) )
for pkg in "${(@)pkgs}"; do
	git ls-files --error-unmatch "$pkg" &>/dev/null || continue
	modernize "$pkg"
done
