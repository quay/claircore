package debian

import (
	"regexp"
)

func init() {
	bullseyeRegex := regexp.MustCompile("bullseye")
	busterRegex := regexp.MustCompile("buster")
	jessieRegex := regexp.MustCompile("jessie")
	stretchRegex := regexp.MustCompile("stretch")
	wheezyRegex := regexp.MustCompile("wheezy")

	resolvers = []vcnRegexp{
		vcnRegexp{Bullseye, bullseyeRegex},
		vcnRegexp{Buster, busterRegex},
		vcnRegexp{Jessie, jessieRegex},
		vcnRegexp{Stretch, stretchRegex},
		vcnRegexp{Wheezy, wheezyRegex},
	}
}

// global array holding compiled vcnRegexp
var resolvers []vcnRegexp

// vcnREgexp determines if a provided string matches a debian version code name as defined by the os-release file
type vcnRegexp struct {
	release Release
	regex   *regexp.Regexp
}

func (r *vcnRegexp) match(s string) bool {
	return r.regex.MatchString(s)
}

// Resolve iterates over each os-release entry and tries to find a release string. if
// found we return the found release in string form. if not found empty string is returned
func ResolveVersionCodeName(osrelease map[string]string) string {
	for _, s := range osrelease {
		for _, r := range resolvers {
			if ok := r.match(s); ok {
				return string(r.release)
			}
		}
	}

	return ""
}
