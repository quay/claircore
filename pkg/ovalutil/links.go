package ovalutil

import (
	"strings"

	"github.com/quay/goval-parser/oval"
)

// Links joins all the links in the cve definition into a single string.
func Links(def oval.Definition) string {
	links := []string{}

	for _, ref := range def.References {
		links = append(links, ref.RefURL)
	}

	for _, ref := range def.Advisory.Refs {
		links = append(links, ref.URL)
	}
	for _, bug := range def.Advisory.Bugs {
		links = append(links, bug.URL)
	}

	s := strings.Join(links, " ")
	return s
}
