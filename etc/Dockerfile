# syntax=docker/dockerfile:experimental
FROM registry.access.redhat.com/ubi8/ubi:8.1 AS install
RUN dnf install -q -y \
	gcc \
	make \
	&&\
	dnf clean all
ARG GO_VERSION
ARG GO_CHECKSUM
RUN curl -sLo /tmp/go.tar.gz "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz" ;\
	echo "${GO_CHECKSUM} /tmp/go.tar.gz" | sha256sum -c -;\
	tar -xz -C /usr/local/ -f /tmp/go.tar.gz;\
	rm /tmp/go.tar.gz;\
	/usr/local/go/bin/go version
ENV GOPATH=/go
ENV GOBIN=/usr/local/bin
ENV PATH="$PATH:/usr/local/go/bin"
WORKDIR $GOPATH
