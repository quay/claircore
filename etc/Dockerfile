# syntax=docker/dockerfile:experimental
FROM registry.access.redhat.com/ubi8/ubi:8.1 AS install
RUN dnf install -q -y \
	gcc \
	make \
	git \
	&&\
	dnf clean all
ARG GO_VERSION
ARG GO_CHECKSUM
RUN arch=$(case "$(uname -m)" in\
		aarch64) echo arm64 ;;\
		x86_64) echo amd64 ;;\
		*) exit 99 ;; esac);\
		curl -sSLfo /tmp/go.tar.gz "https://dl.google.com/go/go${GO_VERSION}.linux-${arch}.tar.gz";\
		test -n "${GO_CHECKSUM}" && { echo "${GO_CHECKSUM} /tmp/go.tar.gz" | sha256sum -c - || exit 99; };\
		tar -xz -C /usr/local/ -f /tmp/go.tar.gz && rm /tmp/go.tar.gz && /usr/local/go/bin/go version
ENV GOPATH=/go
ENV GOBIN=/usr/local/bin
ENV PATH="$PATH:/usr/local/go/bin"
WORKDIR $GOPATH
