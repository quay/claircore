package oval

import (
	"encoding/xml"
)

// Root : root object
type Root struct {
	XMLName     xml.Name    `xml:"oval_definitions"`
	Generator   Generator   `xml:"generator"`
	Definitions Definitions `xml:"definitions"`
	Tests       Tests       `xml:"tests"`
	Objects     Objects     `xml:"objects"`
	States      States      `xml:"states"`
}

// Generator : >generator
type Generator struct {
	XMLName        xml.Name `xml:"generator"`
	ProductName    string   `xml:"product_name"`
	ProductVersion string   `xml:"product_version"`
	SchemaVersion  string   `xml:"schema_version"`
	Timestamp      string   `xml:"timestamp"`
}

// Definitions : >definitions
type Definitions struct {
	XMLName     xml.Name     `xml:"definitions"`
	Definitions []Definition `xml:"definition"`
}

// Definition : >definitions>definition
type Definition struct {
	XMLName     xml.Name    `xml:"definition"`
	ID          string      `xml:"id,attr"`
	Class       string      `xml:"class,attr"`
	Title       string      `xml:"metadata>title"`
	Affecteds   []Affected  `xml:"metadata>affected"`
	References  []Reference `xml:"metadata>reference"`
	Description string      `xml:"metadata>description"`
	Advisory    Advisory    `xml:"metadata>advisory"` // RedHat, Oracle, Ubuntu
	Debian      Debian      `xml:"metadata>debian"`   // Debian
	Criteria    Criteria    `xml:"criteria"`
}

// Criteria : >definitions>definition>criteria
type Criteria struct {
	XMLName    xml.Name    `xml:"criteria"`
	Operator   string      `xml:"operator,attr"`
	Criterias  []Criteria  `xml:"criteria"`
	Criterions []Criterion `xml:"criterion"`
}

// Criterion : >definitions>definition>criteria>*>criterion
type Criterion struct {
	XMLName xml.Name `xml:"criterion"`
	Negate  bool     `xml:"negate,attr"`
	TestRef string   `xml:"test_ref,attr"`
	Comment string   `xml:"comment,attr"`
}

// Affected : >definitions>definition>metadata>affected
type Affected struct {
	XMLName   xml.Name `xml:"affected"`
	Family    string   `xml:"family,attr"`
	Platforms []string `xml:"platform"`
}

// Reference : >definitions>definition>metadata>reference
type Reference struct {
	XMLName xml.Name `xml:"reference"`
	Source  string   `xml:"source,attr"`
	RefID   string   `xml:"ref_id,attr"`
	RefURL  string   `xml:"ref_url,attr"`
}

// Advisory : >definitions>definition>metadata>advisory
// RedHat and Ubuntu OVAL
type Advisory struct {
	XMLName         xml.Name   `xml:"advisory"`
	Severity        string     `xml:"severity"`
	Cves            []Cve      `xml:"cve"`
	Bugzillas       []Bugzilla `xml:"bugzilla"`
	AffectedCPEList []string   `xml:"affected_cpe_list>cpe"`
	Refs            []Ref      `xml:"ref"` // Ubuntu Only
	Bugs            []Bug      `xml:"bug"` // Ubuntu Only
	Issued          struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	Updated struct {
		Date string `xml:"date,attr"`
	} `xml:"updated"`
}

// Ref : >definitions>definition>metadata>advisory>ref
// Ubuntu OVAL
type Ref struct {
	XMLName xml.Name `xml:"ref"`
	URL     string   `xml:",chardata"`
}

// Bug : >definitions>definition>metadata>advisory>bug
// Ubuntu OVAL
type Bug struct {
	XMLName xml.Name `xml:"bug"`
	URL     string   `xml:",chardata"`
}

// Cve : >definitions>definition>metadata>advisory>cve
// RedHat OVAL
type Cve struct {
	XMLName xml.Name `xml:"cve"`
	CveID   string   `xml:",chardata"`
	Cvss2   string   `xml:"cvss2,attr"`
	Cvss3   string   `xml:"cvss3,attr"`
	Cwe     string   `xml:"cwe,attr"`
	Impact  string   `xml:"impact,attr"`
	Href    string   `xml:"href,attr"`
	Public  string   `xml:"public,attr"`
}

// Bugzilla : >definitions>definition>metadata>advisory>bugzilla
// RedHat OVAL
type Bugzilla struct {
	XMLName xml.Name `xml:"bugzilla"`
	ID      string   `xml:"id,attr"`
	URL     string   `xml:"href,attr"`
	Title   string   `xml:",chardata"`
}

// Debian : >definitions>definition>metadata>debian
type Debian struct {
	XMLName  xml.Name `xml:"debian"`
	MoreInfo string   `xml:"moreinfo"`
	Date     string   `xml:"date"`
}

// Tests : >tests
type Tests struct {
	XMLName        xml.Name        `xml:"tests"`
	LineTests      []LineTest      `xml:"line_test"`
	Version55Tests []Version55Test `xml:"version55_test"`
}

// LineTest : >tests>line_test
type LineTest struct {
	XMLName       xml.Name    `xml:"line_test"`
	ID            string      `xml:"id,attr"`
	StateOperator string      `xml:"state_operator,attr"`
	ObjectRefs    []ObjectRef `xml:"object"`
	StateRefs     []StateRef  `xml:"state"`
	Comment       string      `xml:"comment,attr"`
}

// Version55Test : >tests>version55_test
type Version55Test struct {
	XMLName       xml.Name    `xml:"version55_test"`
	ID            string      `xml:"id,attr"`
	StateOperator string      `xml:"state_operator,attr"`
	ObjectRefs    []ObjectRef `xml:"object"`
	StateRefs     []StateRef  `xml:"state"`
	Comment       string      `xml:"comment,attr"`
}

// ObjectRef : >tests>line_test>object-object_ref
//           : >tests>version55_test>object-object_ref
type ObjectRef struct {
	XMLName   xml.Name `xml:"object"`
	ObjectRef string   `xml:"object_ref,attr"`
}

// StateRef : >tests>line_test>state-state_ref
//          : >tests>version55_test>state-state_ref
type StateRef struct {
	XMLName  xml.Name `xml:"state"`
	StateRef string   `xml:"state_ref,attr"`
}

// Objects : >objects
type Objects struct {
	XMLName          xml.Name          `xml:"objects"`
	LineObjects      []LineObject      `xml:"line_object"`
	Version55Objects []Version55Object `xml:"version55_object"`
}

// LineObject : >objects>line_object
type LineObject struct {
	XMLName         xml.Name `xml:"line_object"`
	ID              string   `xml:"id,attr"`
	ShowSubcommands []string `xml:"show_subcommand"`
}

// Version55Object : >objects>version55_object
type Version55Object struct {
	XMLName xml.Name `xml:"version55_object"`
	ID      string   `xml:"id,attr"`
}

// States : >states
type States struct {
	XMLName         xml.Name         `xml:"states"`
	LineStates      []LineState      `xml:"line_state"`
	Version55States []Version55State `xml:"version55_state"`
}

// LineState : >states>line_state
type LineState struct {
	XMLName        xml.Name   `xml:"line_state"`
	ID             string     `xml:"id,attr"`
	ShowSubcommand string     `xml:"show_subcommand"`
	ConfigLine     ConfigLine `xml:"config_line"`
}

// ConfigLine : >states>line_state>config_line
type ConfigLine struct {
	XMLName   xml.Name `xml:"config_line"`
	Body      string   `xml:",chardata"`
	Operation string   `xml:"operation,attr"`
}

// Version55State : >states>version55_state
type Version55State struct {
	XMLName       xml.Name `xml:"version55_state"`
	ID            string   `xml:"id,attr"`
	VersionString string   `xml:"version_string"`
}
