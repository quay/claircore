package postgres

// This is one massive command, sorry.
//
// Splitting it is not allowed.

//go:generate go run ../../../cmd/cctool report -dump -index-fmt "testdata/{{zipSan .}}.index.json" -report-fmt "testdata/{{zipSan .}}.report.json" -manifest-fmt /dev/null docker.io/library/amazonlinux:1 docker.io/library/debian:10 docker.io/library/debian:9 docker.io/library/debian:8 docker.io/mitmproxy/mitmproxy:4.0.1 docker.io/library/ubuntu:16.04 docker.io/library/ubuntu:18.04 docker.io/library/ubuntu:19.10 docker.io/library/ubuntu:20.04 registry.access.redhat.com/ubi8/ubi
