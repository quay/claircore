#!/bin/sh
MAJOR_VERSION=${1?missing required argument: language version}

curl -sSfL 'https://golang.org/dl/?mode=json&include=all' |
jq -r --arg 'v' "$MAJOR_VERSION" '[
	.[] |
	.version |
	select(
		[
			contains("go\($v)"),
			(contains("rc") | not)
		] |
		all
	) |
	ltrimstr("go")
] |
first'
