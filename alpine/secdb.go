package alpine

// Details define a package's name and relevant security fixes included in a
// given version.
type Details struct {
	Name string `json:"name"`
	// Fixed package version string mapped to an array of CVE ids affecting the
	// package.
	Secfixes map[string][]string `json:"secfixes"`
}

// Package wraps the Details.
type Package struct {
	Pkg Details `json:"pkg"`
}

// SecurityDB is the security database structure.
type SecurityDB struct {
	Distroversion string    `json:"distroversion"`
	Reponame      string    `json:"reponame"`
	Urlprefix     string    `json:"urlprefix"`
	Apkurl        string    `json:"apkurl"`
	Packages      []Package `json:"packages"`
}
