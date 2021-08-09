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
RUN if [ `uname -m` = "aarch64" ] ; then curl -sLo /tmp/go.tar.gz "https://dl.google.com/go/go${GO_VERSION}.linux-arm64.tar.gz" ; else curl -sLo /tmp/go.tar.gz "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz" ; fi \
	&& [ -z "${GO_CHECKSUM}" ] || echo "${GO_CHECKSUM} /tmp/go.tar.gz" | sha256sum -c -;\
	tar -xz -C /usr/local/ -f /tmp/go.tar.gz;\
	rm /tmp/go.tar.gz;\
	/usr/local/go/bin/go version
ENV GOPATH=/go
ENV GOBIN=/usr/local/bin
ENV PATH="$PATH:/usr/local/go/bin"
WORKDIR $GOPATH
