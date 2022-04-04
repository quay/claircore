The `list.xml.*` files in here are from a manual walk of the S3 API.
The base64 on the end of the file name is the continuation token.
See ../osv_test.go:/ServeHTTP for an explanation.

Database dumps of the OSV ecosystems can be placed in the testdata directory to help debug parser problems.
The ecosystem name should be lower-cased and replace "all".
For example, to fetch all the ecosystems:

	#!/bin/sh
	for e in crates.io Go Maven npm NuGet Packagist PyPI RubyGems
	do
		wget -c -O "$(git rev-parse --show-toplevel)/updater/osv/testdata/$(echo $e | tr A-Z a-z).zip"\
			"https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip"
	done
