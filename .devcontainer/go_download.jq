[
	.[] |
	select(
		(.version | startswith("go\($ENV.GO_VERSION)"))
		and
		.stable
	) |
	.files[] |
	select(
		.os==$ENV.TARGETOS
		and
		.arch==$ENV.TARGETARCH
	)
] |
first |
@uri "https://golang.org/dl/\(.filename)" |
@sh "curl -sSfL \(.) | tar xzC /usr/local"
