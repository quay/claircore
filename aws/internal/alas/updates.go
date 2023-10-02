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

package alas

import (
	"encoding/xml"
	"fmt"
	"time"
)

type Updates struct {
	Updates []Update `xml:"update"`
}

type Update struct {
	Author      string      `xml:"author,attr"`
	From        string      `xml:"from,attr"`
	Status      string      `xml:"status,attr"`
	Type        string      `xml:"type,attr"`
	Version     string      `xml:"version,attr"`
	ID          string      `xml:"id"`
	Title       string      `xml:"title"`
	Issued      DateElem    `xml:"issued"`
	Updated     DateElem    `xml:"updated"`
	Severity    string      `xml:"severity"`
	Description string      `xml:"description"`
	References  []Reference `xml:"references>reference"`
	Packages    []Package   `xml:"pkglist>collection>package"`
}

type DateElem struct {
	Date `xml:"date,attr"`
}

type Date time.Time

var _ xml.UnmarshalerAttr = (*Date)(nil)

// UnmarshalXMLAttr implements [xml.UnmarshalerAttr].
func (d *Date) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	if attr.Name.Local != `date` {
		return fmt.Errorf("unexpected attr name: %q", attr.Name.Local)
	}
	fmts := []string{
		"2006-01-02 15:04", time.DateTime,
	}
	var t time.Time
	for _, f := range fmts {
		t, err = time.Parse(f, attr.Value)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("parsing date attr: %w", err)
	}
	*d = Date(t)
	return nil
}

type Reference struct {
	Href  string `xml:"href,attr"`
	ID    string `xml:"id,attr"`
	Title string `xml:"title,attr"`
	Type  string `xml:"type,attr"`
}

type Package struct {
	Name     string `xml:"name,attr"`
	Epoch    string `xml:"epoch,attr"`
	Version  string `xml:"version,attr"`
	Release  string `xml:"release,attr"`
	Arch     string `xml:"arch,attr"`
	Filename string `xml:"filename"`
}
