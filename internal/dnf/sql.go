package dnf

import _ "embed" // embed sql

// Return one column containing the repoid.
// Takes six arguments, in order:
//   - the "removed" enum
//   - name
//   - epoch
//   - version
//   - release
//   - arch
//
//go:embed sql/repoid_for_package.sql
var repoidForPackage string

// Return one column containing the repoids.
// Takes one argument:
//   - the "removed" enum
//
//go:embed sql/all_repoids.sql
var allRepoids string
