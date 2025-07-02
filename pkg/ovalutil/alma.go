package ovalutil

import (
	"errors"
	"regexp"

	"github.com/quay/goval-parser/oval"
)

const (
	ALEADefinition DefinitionType = "alea"
	ALBADefinition DefinitionType = "alba"
	ALSADefinition DefinitionType = "alsa"
)

var almaDefinitionTypeRegex = regexp.MustCompile(`^oval:org\.almalinux\.([a-z]+):def:\d+$`)

// GetAlmaDefinitionType parses an OVAL definition and extracts its type from ID.
func GetAlmaDefinitionType(def oval.Definition) (DefinitionType, error) {
	match := almaDefinitionTypeRegex.FindStringSubmatch(def.ID)
	if len(match) != 2 { // we should have match of the whole string and one submatch
		return "", errors.New("cannot parse definition ID for its type")
	}
	return DefinitionType(match[1]), nil
}
