package ubuntu

import (
	"regexp"
)

func init() {
	bionicRegex := regexp.MustCompile("[Bb]ionic")
	cosmicRegex := regexp.MustCompile("[Cc]osmic")
	discoRegex := regexp.MustCompile("[Dd]isco")
	trustyRegex := regexp.MustCompile("[Tt]rusty")
	xenialRegex := regexp.MustCompile("[Xx]enial")

	resolvers = []vcnRegexp{
		vcnRegexp{Bionic, bionicRegex},
		vcnRegexp{Cosmic, cosmicRegex},
		vcnRegexp{Disco, discoRegex},
		vcnRegexp{Trusty, trustyRegex},
		vcnRegexp{Xenial, xenialRegex},
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
