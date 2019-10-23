# syntax=docker/dockerfile:experimental
FROM registry.access.redhat.com/ubi8/ubi:8.0 AS install
RUN dnf install -y gcc &&\
	dnf clean all
RUN curl -sLo /tmp/go.tar.gz https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz;\
	echo "0804bf02020dceaa8a7d7275ee79f7a142f1996bfd0c39216ccb405f93f994c0 /tmp/go.tar.gz" | sha256sum -c -;\
	tar -xz -C /usr/local/ -f /tmp/go.tar.gz;\
	rm /tmp/go.tar.gz;\
	/usr/local/go/bin/go version
ENV GOPATH=/go
ENV GOBIN=/usr/local/bin
ENV PATH="$PATH:/usr/local/go/bin"
WORKDIR $GOPATH
