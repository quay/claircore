docker ?= docker

# generates mocks of interfaces for testing
.PHONY: genmocks
genmocks:
	@command -v mockgen >/dev/null || go install github.com/golang/mock/mockgen
	go generate ./...

# spawns a shell in the golang container with our source mounted in. leaves you at a tty
.PHONY: docker-shell
docker-shell:
	$(docker) run --rm -it -p 8080:8080 -v $(shell pwd):/claircore golang:1.12 bash -c 'cd /claircore/cmd/libscanhttp; go install; cd -; /bin/bash'

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

# spawns a postgres database bootstrapped with the libscan schema. makes itself available locally at 5434
# currently integration tests hardcode this port
.PHONY: libscan-db-up
libscan-db-up:
	$(docker) run -d --name libscan -e POSTGRES_USER=libscan -e POSTGRES_DB=libscan -p 5434:5432 postgres
	$(docker) exec -it libscan bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
	psql -h localhost -p 5434 -U libscan -d libscan -f internal/scanner/postgres/bootstrap.sql

# kills the libscan database
.PHONY: libscan-db-down
libscan-db-down:
	$(docker) kill libscan
	$(docker) rm libscan

# kills the libscan database and spawn a new one
.PHONY: libscan-db-restart
libscan-db-restart:
	-make libscan-db-down
	make libscan-db-up

# spawns a postgres database bootstrapped with the libvuln schema. makes itself available locally at 5435
# currently integration tests hardcode this port
.PHONY: libvuln-db-up
libvuln-db-up:
	$(docker) run -d --name libvuln -e POSTGRES_USER=libvuln -e POSTGRES_DB=libvuln -p 5435:5432 postgres
	$(docker) exec -it libvuln bash -c 'while ! pg_isready; do echo "waiting for postgres"; sleep 2; done'
	psql -h localhost -p 5435 -U libvuln -d libvuln -f internal/vulnstore/postgres/bootstrap.sql

# kills the libvuln database
.PHONY: libvuln-db-down
libvuln-db-down:
	$(docker) kill libvuln
	$(docker) rm libvuln

# kills the libvuln database and spawns a new one 
.PHONY: libvuln-db-restart
libvuln-db-restart:
	-make libvuln-db-down
	make libvuln-db-up

