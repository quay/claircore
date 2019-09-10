projectSourcePath := github.com/tadasv/go-dpkg
dockerMountPath := /go/src/$(projectSourcePath)

docker-shell:
	docker exec -ti go-dpkg-dev bash

docker-clean:
	docker rm go-dpkg-dev

docker-dev:
	docker run --name go-dpkg-dev -ti -d -w $(dockerMountPath) -v $(PWD):$(dockerMountPath) golang:1.6.2 bash
