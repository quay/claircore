docker ?= docker
docker-compose ?= docker-compose

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
	$(docker-compose) up -d --force-recreate claircore-db

.PHONY: libindexhttp-restart
libindexhttp-restart:
	$(docker-compose) up -d --force-recreate libindexhttp

.PHONY: libvulnhttp-restart
libvulnhttp-restart:
	$(docker-compose) up -d --force-recreate libvulnhttp

.PHONY: podman-dev-up
podman-dev-up:
	podman pod create\
		--publish 5434\
		--publish 8080\
		--publish 8081\
		--name claircore-dev
	podman create\
		--pod claircore-dev\
		--name claircore-database\
		--env POSTGRES_USER=claircore\
		--env POSTGRES_DB=claircore\
		--env POSTGRES_INITDB_ARGS="--no-sync"\
		--env PGPORT=5434\
		--expose 5434\
		--health-cmd "pg_isready -U claircore -d claircore"\
		postgres:11
	podman pod start claircore-dev
	until podman healthcheck run claircore-database; do sleep 2; done
	go mod vendor
	podman create\
		--pod claircore-dev\
		--name libindexhttp\
		--env HTTP_LISTEN_ADDR="0.0.0.0:8080"\
		--env CONNECTION_STRING="host=localhost port=5434 user=claircore dbname=claircore sslmode=disable"\
		--env SCAN_LOCK_RETRY=1\
		--env LAYER_SCAN_CONCURRENCY=10\
		--env LOG_LEVEL="debug"\
		--expose 8080\
		--volume $$(git rev-parse --show-toplevel)/:/src/claircore/:z\
		quay.io/claircore/golang:1.13.3\
		bash -c 'cd /src/claircore/cmd/libindexhttp; exec go run -mod vendor .'
	podman create\
		--pod claircore-dev\
		--name libvulnhttp\
		--env HTTP_LISTEN_ADDR="0.0.0.0:8081"\
		--env CONNECTION_STRING="host=localhost port=5434 user=claircore dbname=claircore sslmode=disable"\
		--env LOG_LEVEL="debug"\
		--expose 8081\
		--volume $$(git rev-parse --show-toplevel)/:/src/claircore/:z\
		quay.io/claircore/golang:1.13.3\
		bash -c 'cd /src/claircore/cmd/libvulnhttp; exec go run -mod vendor .'
	podman pod start claircore-dev

# TODO(hank) When the latest podman lands with 'generate systemd' support for
# pods, use it here.

.PHONY: podman-dev-down
podman-dev-down:
	podman pod stop -t 10 claircore-dev
	true $(foreach c,claircore-database libindexhttp libvulnhttp,&& podman rm -v $c)
	podman pod rm claircore-dev

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
