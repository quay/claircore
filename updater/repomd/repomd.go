// Copyright 2019 RedHat
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repomd

import (
	"errors"
	"net/url"
)

type RepoType string

var ErrRepoNotFound = errors.New("Repo not found")

const (
	PrimaryDB  RepoType = "primary_db"
	OtherDB    RepoType = "other_db"
	GroupGZ    RepoType = "group_gz"
	Group      RepoType = "group"
	FileLists  RepoType = "filelists_db"
	UpdateInfo RepoType = "updateinfo"
)

type RepoMD struct {
	XMLNS    string `xml:"xmlns,attr"`
	XMLRPM   string `xml:"xmlns rpm,attr"`
	Revision int    `xml:"revision"`
	RepoList []Repo `xml:"data"`
}

type Repo struct {
	Type            string   `xml:"type,attr"`
	Checksum        Checksum `xml:"checksum"`
	OpenChecksum    Checksum `xml:"open-checksum"`
	Location        Location `xml:"location"`
	Timestamp       int      `xml:"timestamp"`
	DatabaseVersion int      `xml:"database_version"`
	Size            int      `xml:"size"`
	OpenSize        int      `xml:"open-size"`
}

type Checksum struct {
	Sum  string `xml:",chardata"`
	Type string `xml:"type,attr"`
}

type Location struct {
	Href string `xml:"href,attr"`
}

// Repo returns a Repo struct per the specified RepoType.
// If a mirror url is provided a fully qualified Repo.Location.Href is returned
// A ErrRepoNotFound error is returned if the RepoType cannot be located.
func (md *RepoMD) Repo(t RepoType, mirror string) (*Repo, error) {
	for i := range md.RepoList {
		repo := &md.RepoList[i]
		if repo.Type != string(t) {
			continue
		}
		if mirror != "" {
			u, err := url.Parse(mirror)
			if err != nil {
				return nil, err
			}
			href, err := u.Parse(repo.Location.Href)
			if err != nil {
				return nil, err
			}
			repo.Location.Href = href.String()
		}
		return repo, nil
	}
	return nil, ErrRepoNotFound
}
