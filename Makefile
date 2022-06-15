docker ?= docker
docker-compose ?= docker-compose

# clears any go code in various caches
.PHONY: clear-cache
clear-cache:
	go clean -cache -testcache -modcache
	test -d $${XDG_CACHE_HOME:-$${HOME}/.cache}/clair-testing && rm -rf $${XDG_CACHE_HOME:-$${HOME}/.cache}/clair-testing

.PHONY: generate
generate:
	@command -v mockgen >/dev/null || go install github.com/golang/mock/mockgen
	@command -v stringer >/dev/null || go install golang.org/x/tools/cmd/stringer
	find . -name go.mod -execdir \
	go generate ./... \;

# Runs integration tests. An embedded postgres binary will be fetched if the
# environment variable "POSTGRES_CONNECTION_STRING" isn't set.
.PHONY: integration integration-v
integration:
	find . -name go.mod -execdir \
	go test -count=1 -race -tags integration ./... \;

integration-v:
	find . -name go.mod -execdir \
	go test -count=1 -race -v -tags integration ./... \;

# runs unit tests. no db necessary
.PHONY: unit unit-v
unit:
	find . -name go.mod -execdir \
	go test -race ./... \;

unit-v:
	find . -name go.mod -execdir \
	go test -race -v ./... \;

# run bench marks - db must be available. use the db commands below to ensure
.PHONY: bench
bench:
	find . -name go.mod -execdir \
	go test -tags integration -run=xxx -bench ./... \;

GO_VERSION ?= 1.18
GO_CHECKSUM ?= e85278e98f57cdb150fe8409e6e5df5343ecb13cebf03a5d5ff12bd55a80264f
.PHONY: baseimage
baseimage:
	podman build -f etc/Dockerfile -t quay.io/projectquay/golang:$(GO_VERSION) \
		--build-arg GO_VERSION=$(GO_VERSION) \
	   	--build-arg GO_CHECKSUM=$(GO_CHECKSUM) \
		etc

book: $(wildcard docs/*) book.toml
	mdbook build
