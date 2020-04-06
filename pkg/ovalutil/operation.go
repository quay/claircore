package ovalutil

import (
	"regexp"
	"strings"

	"github.com/quay/goval-parser/oval"
)

// Operation check if values match based on given operation
func Operation(value, requiredValue string, operation oval.Operation) bool {
	switch operation {
	case oval.OpEquals:
		return value == requiredValue
	case oval.OpNotEquals:
		return value != requiredValue
	case oval.OpCaseInsensitiveEquals:
		return strings.EqualFold(value, requiredValue)
	case oval.OpCaseInsensitiveNotEquals:
		return !strings.EqualFold(value, requiredValue)
	case oval.OpGreaterThan:
		return value > requiredValue
	case oval.OpLessThan:
		return value < requiredValue
	case oval.OpGreaterThanOrEqual:
		return value >= requiredValue
	case oval.OpLessThanOrEqual:
		return value <= requiredValue
	case oval.OpPatternMatch:
		exp, err := regexp.Compile(requiredValue)
		if err != nil {
			return false
		}
		return exp.Match([]byte(value))

	default:
		return false
	}
}
