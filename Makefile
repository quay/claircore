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
	@command -v mockgen >/dev/null || go install github.com/golang/mock/mockgen
	go generate ./...

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

.PHONY: local-dev-up
local-dev-up:
	$(docker-compose) up -d claircore-db
	$(docker) exec -it claircore-db bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
	go mod vendor
	$(docker-compose) up -d libindexhttp
	$(docker-compose) up -d libvulnhttp

.PHONY: local-dev-down
local-dev-down:
	$(docker-compose) down

.PHONY: local-dev-logs
local-dev-logs:
	$(docker-compose) logs -f

.PHONY: claircore-db-up
claircore-db-up:
	$(docker-compose) up -d claircore-db
	$(docker) exec -it claircore-db bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'

.PHONY: claircore-db-restart
claircore-db-restart:
	$(docker) kill claircore-db && $(docker) rm claircore-db
	make claircore-db-up

.PHONY: libindexhttp-restart
libindexhttp-restart:
	$(docker-compose) up -d --force-recreate libindexhttp

.PHONY: libvulnhttp-restart
libvulnhttp-restart:
	$(docker-compose) up -d --force-recreate libvulnhttp

etc/podman.yaml: etc/podman.yaml.in
	m4 -D_ROOT=$$(git rev-parse --show-toplevel) <$< >$@

.PHONY: podman-dev-up
podman-dev-up: etc/podman.yaml
	podman play kube $<

.PHONY: podman-dev-down
podman-dev-down: etc/podman.yaml
	podman pod stop -t 10 $$(awk '/^  name:/{print $$NF}' <$<)
	podman pod rm $$(awk '/^  name:/{print $$NF}' <$<)

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
