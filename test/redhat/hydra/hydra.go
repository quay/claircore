// Package hydra contains common types for dealing with the Red Hat Search API
// (aka hydra).
//
// I'm currently unaware of comprehensive documentation. This package contains
// just the observed structure needed for claircore's test infrastructure.
package hydra

// Response is the top-level response from the hydra service.
//
// This has just enough structure to get at the needed data.
type Response struct {
	Response struct {
		Docs []Doc `json:"docs"`
	} `json:"response"`
}

// Doc is an individual search result for "ContainerRepository" documents.
//
// This has just enough structure to get at the needed data.
type Doc struct {
	ID         string   `json:"id"`
	Repository string   `json:"repository"`
	Registry   string   `json:"registry"`
	Layers     []string `json:"parsed_data_layers"`
}
