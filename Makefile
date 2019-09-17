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
	go test -p 1 -race -tags integration ./...

# runs integration test which may fail on darwin but must succeed on linux/unix
# using the docker-shell makefile first will drop you into a unix container where
# you may run this target if you are on darwin/macOS
.PHONY: integration-unix
integration-unix:
	go test -p 1 -race -tags unix ./...

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
	go test -race -v -tags integration ./...

# same as unit but with verbose
.PHONY: unit-v
unit-v:
	go test -race -v ./...

.PHONY: local-dev-up
local-dev-up:
	$(docker-compose) up -d claircore-db
	$(docker) exec -it claircore_claircore-db_1 bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
	$(docker-compose) up -d libscanhttp
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

.PHONY: libscanhttp-restart
libscanhttp-restart:
	$(docker-compose) up -d --force-recreate libscanhttp

.PHONY: libvulnhttp-restart
libvulnhttp-restart:
	$(docker-compose) up -d --force-recreate libvulnhttp
