# syntax=docker/dockerfile:1
FROM quay.io/projectquay/golang:1.17 AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN go build -trimpath -buildmode=plugin

FROM scratch
COPY --from=build /build/matcher.so /
