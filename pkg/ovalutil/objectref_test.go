package ovalutil

import (
	"context"
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/goval-parser/oval"
)

// A test element is only required to carry an object reference; a feed that
// omits it still parses.
const missingObjectRef = `<oval_definitions>
  <definitions>
    <definition id="oval:com.example:def:1" class="patch">
      <metadata><title>example</title></metadata>
      <criteria>
        <criterion test_ref="oval:com.example:tst:1" comment="package is installed"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <%s id="oval:com.example:tst:1" check="at least one" comment="package is installed"/>
  </tests>
</oval_definitions>`

func protoVuln(oval.Definition) ([]*claircore.Vulnerability, error) {
	return []*claircore.Vulnerability{{Name: "example"}}, nil
}

func TestDefsToVulnsWithoutObjectRef(t *testing.T) {
	for _, kind := range []string{"rpminfo_test", "dpkginfo_test"} {
		t.Run(kind, func(t *testing.T) {
			root := &oval.Root{}
			if err := xml.Unmarshal([]byte(fmt.Sprintf(missingObjectRef, kind)), root); err != nil {
				t.Fatalf("parsing the oval document: %v", err)
			}

			var (
				vulns []*claircore.Vulnerability
				err   error
			)
			switch kind {
			case "rpminfo_test":
				vulns, err = RPMDefsToVulns(context.Background(), root, protoVuln)
			case "dpkginfo_test":
				vulns, err = DpkgDefsToVulns(context.Background(), root, protoVuln, func(_ oval.Definition, name *oval.DpkgName) []string {
					return []string{name.Body}
				})
			}
			if err != nil {
				t.Fatalf("got an error: %v", err)
			}
			if len(vulns) != 0 {
				t.Errorf("expected the criterion to be skipped, got %d vulnerabilities", len(vulns))
			}
		})
	}
}
