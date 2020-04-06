package ovalutil

import (
	"testing"

	"github.com/quay/goval-parser/oval"
)

// TestOperation tests if given value match with requited based on operation type
func TestOperation(t *testing.T) {
	t.Parallel()

	type testcase struct {
		Name          string
		Value         string
		RequiredValue string
		Operation     oval.Operation
		Want          bool
	}
	testcases := []testcase{
		{
			Name:          "equal",
			Value:         "foo",
			RequiredValue: "foo",
			Operation:     oval.OpEquals,
			Want:          true,
		},
		{
			Name:          "equal-false",
			Value:         "Foo",
			RequiredValue: "foo",
			Operation:     oval.OpEquals,
			Want:          false,
		},
		{
			Name:          "not-match",
			Value:         "foo",
			RequiredValue: "bar",
			Operation:     oval.OpNotEquals,
			Want:          true,
		},
		{
			Name:          "not-match-false",
			Value:         "foo",
			RequiredValue: "foo",
			Operation:     oval.OpNotEquals,
			Want:          false,
		},
		{
			Name:          "OpCaseInsensitiveEquals",
			Value:         "foo",
			RequiredValue: "FOO",
			Operation:     oval.OpCaseInsensitiveEquals,
			Want:          true,
		},
		{
			Name:          "OpCaseInsensitiveNotEquals",
			Value:         "foo2",
			RequiredValue: "FOO",
			Operation:     oval.OpCaseInsensitiveNotEquals,
			Want:          true,
		},
		{
			Name:          "OpGreaterThan",
			Value:         "2",
			RequiredValue: "1",
			Operation:     oval.OpGreaterThan,
			Want:          true,
		},
		{
			Name:          "OpGreaterThan-false",
			Value:         "1",
			RequiredValue: "2",
			Operation:     oval.OpGreaterThan,
			Want:          false,
		},
		{
			Name:          "OpLessThan",
			Value:         "1",
			RequiredValue: "2",
			Operation:     oval.OpLessThan,
			Want:          true,
		},
		{
			Name:          "OpLessThan-false",
			Value:         "2",
			RequiredValue: "1",
			Operation:     oval.OpLessThan,
			Want:          false,
		},
		{
			Name:          "OpGreaterThanOrEqual",
			Value:         "2",
			RequiredValue: "1",
			Operation:     oval.OpGreaterThanOrEqual,
			Want:          true,
		},
		{
			Name:          "OpGreaterThanOrEqual-false",
			Value:         "1",
			RequiredValue: "2",
			Operation:     oval.OpGreaterThanOrEqual,
			Want:          false,
		},
		{
			Name:          "OpLessThanOrEqual",
			Value:         "1",
			RequiredValue: "2",
			Operation:     oval.OpLessThanOrEqual,
			Want:          true,
		},
		{
			Name:          "OpLessThanOrEqual-false",
			Value:         "2",
			RequiredValue: "1",
			Operation:     oval.OpLessThanOrEqual,
			Want:          false,
		},
		{
			Name:          "pattern-match",
			Value:         "foo",
			RequiredValue: "foo|bar",
			Operation:     oval.OpPatternMatch,
			Want:          true,
		},
		{
			Name:          "pattern-not-match",
			Value:         "foo",
			RequiredValue: "bar|bar",
			Operation:     oval.OpPatternMatch,
			Want:          false,
		},
	}

	for _, testCase := range testcases {
		t.Run(
			testCase.Name,
			func(t *testing.T) {
				got := Operation(
					testCase.Value,
					testCase.RequiredValue,
					testCase.Operation,
				)
				if got != testCase.Want {
					t.Errorf("got: %v, want: %v", got, testCase.Want)
				}
			},
		)
	}

}
