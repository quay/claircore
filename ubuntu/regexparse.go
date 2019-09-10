package ubuntu

import (
	"regexp"
	"strings"
)

var reNotFixed = regexp.MustCompile(`^(.+) package in .+ affected and needs fixing.$`)

func parseNotFixedYet(comment string) (name string, fixVersion string, found bool) {
	// Ubuntu 14
	// The 'php-openid' package in trusty is affected and needs fixing.

	// Ubuntu 16, 18
	// xine-console package in bionic is affected and needs fixing. />
	res := reNotFixed.FindStringSubmatch(comment)
	if len(res) == 2 {
		return trimPkgName(res[1]), "", true
	}
	return "", "", false
}

var reNotDecided = regexp.MustCompile(`^(.+) package in .+ is affected, but a decision has been made to defer addressing it .+$`)

func parseNotDecided(comment string) (name string, fixVersion string, found bool) {
	// Ubuntu 14
	// The 'ruby1.9.1' package in trusty is affected, but a decision has been made to defer addressing it (note: '2019-04-10').

	// Ubuntu 16, 18
	// libxerces-c-samples package in bionic is affected, but a decision has been made to defer addressing it (note: '2019-01-01').
	res := reNotDecided.FindStringSubmatch(comment)
	if len(res) == 2 {
		return trimPkgName(res[1]), "", true
	}
	return "", "", false
}

var reFixed = regexp.MustCompile(`^(.+) package in .+ has been fixed \(note: '([^\s]+).*'\).$`)

func parseFixed(comment string) (name string, fixVersion string, found bool) {
	// Ubuntu 14
	// The 'poppler' package in trusty was vulnerable but has been fixed (note: '0.10.5-1ubuntu2').

	// Ubuntu 16, 18
	// iproute2 package in bionic, is related to the CVE in some way and has been fixed (note: '3.12.0-2').
	res := reFixed.FindStringSubmatch(comment)
	if len(res) == 3 {
		return trimPkgName(res[1]), res[2], true
	}
	return "", "", false
}

func trimPkgName(name string) string {
	name = strings.TrimPrefix(name, "The '")
	return strings.TrimSuffix(name, "'")
}
