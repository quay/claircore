package dnf

import _ "embed" // embed sql

// Return one column containing the repoid.
// Takes two arguments, in order:
//   - the "removed" enum
//   - package name.
//
//go:embed sql/repoid_for_package.sql
var repoidForPackage string

// Return one column containing the repoids.
// Takes one argument:
//   - the "removed" enum
//
//go:embed sql/all_repoids.sql
var allRepoids string
