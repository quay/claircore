package dpkg

import (
	"os"
)

type Package struct {
	Package       string
	Status        string
	Priority      string
	Architecture  string
	MultiArch     string
	Maintainer    string
	Version       string
	Section       string
	InstalledSize int64
	Depends       string
	PreDepends    string
	Description   string
	Source        string
	Homepage      string
}

func ReadPackagesFromFile(fileName string) ([]Package, error) {
	fd, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	parser := NewParser(fd)
	return parser.Parse(), nil
}
