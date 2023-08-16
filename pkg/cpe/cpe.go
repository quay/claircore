// Package cpe provides for handling Common Platform Enumeration (CPE) names.
//
// Deprecated: This package is a re-export of "github.com/quay/claircore/toolkit/types/cpe".
// Users should migrate to that package.
package cpe

import "github.com/quay/claircore/toolkit/types/cpe"

// Attribute is a type for enumerating the valid CPE attributes.
type Attribute = cpe.Attribute

// These are the valid Attributes, in CPE 2.3 binding order.
const (
	Part      = cpe.Part
	Vendor    = cpe.Vendor
	Product   = cpe.Product
	Version   = cpe.Version
	Update    = cpe.Update
	Edition   = cpe.Edition
	Language  = cpe.Language
	SwEdition = cpe.SwEdition
	TargetSW  = cpe.TargetSW
	TargetHW  = cpe.TargetHW
	Other     = cpe.Other
)

// NumAttr is the number of attributes in a 2.3 WFN.
const NumAttr = cpe.NumAttr

// Value represents all the states for an attribute's value.
type Value = cpe.Value

// NewValue constructs a specific value and ensures it's a valid string.
//
// This function does not quote the provided string, only validates that the
// quoting is proper.
func NewValue(v string) (Value, error) {
	return cpe.NewValue(v)
}

// ValueKind indicates what "kind" a value is.
type ValueKind = cpe.ValueKind

// These are the valid states for a wfn attribute's value.
const (
	ValueUnset = cpe.ValueUnset
	ValueAny   = cpe.ValueAny
	ValueNA    = cpe.ValueNA
	ValueSet   = cpe.ValueSet
)

// WFN is a well-formed name as defined by the Common Platform Enumeration (CPE)
// spec: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
//
// This package does not implement binding into URI form.
type WFN = cpe.WFN

// ErrUnset is returned from (WFN).Valid() if it is the zero value.
var ErrUnset = cpe.ErrUnset

// Unbind attempts to unbind a string regardless of it be a formatted string or
// URI.
func Unbind(s string) (WFN, error) {
	return cpe.Unbind(s)
}

// MustUnbind calls Unbind on the provided string, but panics if any errors are
// encountered.
//
// This is primarily useful for static data where any error is a programmer
// error.
func MustUnbind(s string) WFN {
	return cpe.MustUnbind(s)
}

// UnbindURI attempts to unbind a string as CPE 2.2 URI into a WFN.
//
// This function supports unpacking attributes from the "edition" component as
// specified in CPE 2.3.
func UnbindURI(s string) (WFN, error) {
	return cpe.UnbindURI(s)
}

// UnbindFS attempts to unbind a string as CPE 2.3 formatted string into a WFN.
func UnbindFS(s string) (WFN, error) {
	return cpe.UnbindFS(s)
}
