package claircore

import "github.com/quay/claircore/pkg/cpe"

// Repository is a package repository
type Repository struct {
	ID   string  `json:"id,omitempty"`
	Name string  `json:"name,omitempty"`
	Key  string  `json:"key,omitempty"`
	URI  string  `json:"uri,omitempty"`
	CPE  cpe.WFN `json:"cpe,omitempty"`
}
