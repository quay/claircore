package spdx

// Format describes the data format for the SPDX document.
type Format string

const JSONFormat Format = "json"

// Version describes the SPDX version to target.
type Version string

const (
	V2_3 Version = "v2.3"
)
