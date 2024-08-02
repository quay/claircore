docker ?= docker
docker-compose ?= docker-compose

# clears any go code in various caches
.PHONY: clear-cache
clear-cache:
	go clean -cache -testcache -modcache
	test -d $${XDG_CACHE_HOME:-$${HOME}/.cache}/clair-testing && rm -rf $${XDG_CACHE_HOME:-$${HOME}/.cache}/clair-testing

# generates mocks of interfaces for testing
.PHONY: genmocks
genmocks:
	go generate -run mockgen ./...

# Runs integration tests. An embedded postgres binary will be fetched if the
# environment variable "POSTGRES_CONNECTION_STRING" isn't set.
.PHONY: integration
integration:
	go test -count=1 -race -tags integration ./...

# runs unit tests. no db necessary
.PHONY: unit
unit:
	go test -race ./...

# run bench marks - db must be available. use the db commands below to ensure
.PHONY: bench
bench:
	go test -tags integration -run=xxx -bench ./...

# same as integration but with verbose
.PHONY: integration-v
integration-v:
	go test -count=1 -race -v -tags integration ./...

# same as unit but with verbose
.PHONY: unit-v
unit-v:
	go test -race -v ./...

.PHONY: claircore-db-up
claircore-db-up:
	$(docker-compose) up -d claircore-db
	$(docker) exec -it claircore-db bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'

.PHONY: claircore-db-restart
claircore-db-restart:
	$(docker) kill claircore-db && $(docker) rm claircore-db
	make claircore-db-up

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

docs/mermaid.min.js:
	curl -sSfL 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js' >$@
