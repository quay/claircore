package rhcc

import (
	"encoding/xml"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/cpe"
	"github.com/quay/claircore/pkg/rhctag"
)

var goldRepo = claircore.Repository{
	Name: "Red Hat Container Catalog",
	URI:  `https://catalog.redhat.com/software/containers/explore`,
}

type cveMap struct {
	XMLName               xml.Name              `xml:"cvemap"`
	RedHatVulnerabilities []redHatVulnerability `xml:"Vulnerability"`
}

type redHatVulnerability struct {
	XMLName          xml.Name          `xml:"Vulnerability"`
	Name             string            `xml:"name,attr"`
	ThreatSeverity   string            `xml:"ThreatSeverity"`
	AffectedReleases []affectedRelease `xml:"AffectedRelease"`
	Details          []details         `xml:"Details"`
}

type affectedRelease struct {
	XMLName     xml.Name   `xml:"AffectedRelease"`
	Cpe         string     `xml:"cpe,attr"`
	ReleaseDate customTime `xml:"ReleaseDate"`
	Package     string     `xml:"Package"`
	Impact      string     `xml:"impact,attr"`
	Advisory    advisory   `xml:"Advisory"`
}

type advisory struct {
	XMLName xml.Name `xml:"Advisory"`
	Text    string   `xml:",cdata"`
	URL     string   `xml:"url,attr"`
}

type details struct {
	XMLName xml.Name `xml:"Details"`
	Text    string   `xml:",cdata"`
	Source  string   `xml:"source,attr"`
}

type customTime struct {
	time time.Time
}

type consolidatedRelease struct {
	Issued          time.Time
	FixedInVersions *rhctag.Versions
	Severity        string
	AdvisoryLink    string
	AdvisoryName    string
	Cpe             cpe.WFN
}

func (c *customTime) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	const shortForm = "2006-01-02"
	var v string
	d.DecodeElement(&v, &start)
	date := strings.Split(v, "T")
	parse, err := time.Parse(shortForm, date[0])
	if err != nil {
		return err
	}
	*c = customTime{parse}
	return nil
}

func parseContainerPackage(p string) (bool, string, string) {
	parts := strings.Split(p, ":")
	if len(parts) != 2 {
		return false, "", ""
	}
	if !strings.ContainsAny(parts[0], "/") {
		return false, "", ""
	}
	return true, parts[0], parts[1]
}

// Prefer Red Hat descriptions over Mitre ones
func getDescription(ds []details) string {
	rhDetailsIdx := -1
	mitreDetailsIdx := -1
	result := ""
	for idx, d := range ds {
		if d.Source == "Red Hat" {
			rhDetailsIdx = idx
			break
		} else if d.Source == "Mitre" {
			mitreDetailsIdx = idx
		}
	}
	if rhDetailsIdx != -1 {
		result = ds[rhDetailsIdx].Text
		return strings.TrimSpace(result)
	}
	if mitreDetailsIdx != -1 {
		result = ds[mitreDetailsIdx].Text
		return strings.TrimSpace(result)
	}
	return strings.TrimSpace(result)
}
