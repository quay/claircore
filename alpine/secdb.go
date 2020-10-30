package alpine

import (
	"io"

	"gopkg.in/yaml.v3"
)

// Details define a package's name and security fixes for said package
type Details struct {
	Name string `yaml:"name"`
	// fixed package version string mapped to an array of CVE ids affecting the package
	Secfixes map[string][]string `yaml:"secfixes"`
}

// Package wraps the Details
type Package struct {
	Pkg Details `yaml:"pkg"`
}

// SecurityDB is the yaml security database structure
type SecurityDB struct {
	Distroversion string    `yaml:"distroversion"`
	Reponame      string    `yaml:"reponame"`
	Urlprefix     string    `yaml:"urlprefix"`
	Apkurl        string    `yaml:"apkurl"`
	Packages      []Package `yaml:"packages"`
}

func (db *SecurityDB) Parse(contents io.Reader) error {
	// heap allocate if nil
	if db == nil {
		db = &SecurityDB{}
	}

	err := yaml.NewDecoder(contents).Decode(db)
	if err != nil {
		return err
	}
	return nil
}
