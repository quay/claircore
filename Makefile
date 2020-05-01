docker ?= docker
docker-compose ?= docker-compose

# clears any go code in various caches
.PHONY: clear-cache
clear-cache:
	go clean -cache -testcache -modcache

# generates mocks of interfaces for testing
.PHONY: genmocks
genmocks:
	@command -v mockgen >/dev/null || go install github.com/golang/mock/mockgen
	go generate ./...

# runs integration tests. database must be available. use the db commands below to ensure this
.PHONY: integration
integration:
	go test -count=1 -race -tags integration ./...

# runs integration test which may fail on darwin but must succeed on linux/unix
# using the docker-shell makefile first will drop you into a unix container where
# you may run this target if you are on darwin/macOS
.PHONY: integration-unix
integration-unix:
	go test -count=1 -p 1 -race -tags unix ./...

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
	$(docker) exec -it claircore_claircore-db_1 bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
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
	$(docker) exec -it claircore_claircore-db_1 bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'

.PHONY: claircore-db-restart
claircore-db-restart:
	$(docker) kill claircore_claircore-db_1 && $(docker) rm claircore_claircore-db_1
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

GO_VERSION ?= 1.13.5
GO_CHECKSUM ?= 512103d7ad296467814a6e3f635631bd35574cab3369a97a323c9a585ccaa569
.PHONY: baseimage
baseimage:
	buildah bud -f etc/Dockerfile -t quay.io/claircore/golang:$(GO_VERSION) \
		--build-arg GO_VERSION=$(GO_VERSION) \
	   	--build-arg GO_CHECKSUM=$(GO_CHECKSUM) \
		etc

book: $(wildcard docs/*) book.toml
	mdbook build
